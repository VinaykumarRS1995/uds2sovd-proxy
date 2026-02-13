//! TCP connection handler

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::doip::{
    alive_check, diagnostic_message, routing_activation, DoipCodec, DoipMessage, PayloadType,
};
use crate::server::{ServerConfig, SessionManager};
use crate::uds::{UdsHandler, UdsRequest};

/// Response can be single message or multiple (ACK + Response)
enum HandleResult {
    None,
    Single(DoipMessage),
    Multiple(Vec<DoipMessage>),
}

pub struct TcpHandler<H: UdsHandler> {
    config: Arc<ServerConfig>,
    sessions: Arc<SessionManager>,
    uds_handler: Arc<H>,
}

impl<H: UdsHandler> TcpHandler<H> {
    pub fn new(
        config: Arc<ServerConfig>,
        sessions: Arc<SessionManager>,
        uds_handler: Arc<H>,
    ) -> Self {
        Self {
            config,
            sessions,
            uds_handler,
        }
    }

    pub async fn handle_connection(&self, stream: TcpStream) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get peer address: {}", e);
                return;
            }
        };

        info!("New TCP connection from {}", peer_addr);

        let session = self.sessions.create_session(peer_addr);
        let session_id = session.id;

        let mut framed = Framed::new(stream, DoipCodec::new());

        'connection_loop: loop {
            match framed.next().await {
                Some(Ok(msg)) => {
                    debug!("Received message: {:?}", msg.header);

                    // Store the incoming protocol version to mirror it in responses
                    let incoming_version = msg.header.version;

                    let result = self.handle_message(session_id, msg, incoming_version).await;

                    match result {
                        HandleResult::None => {}
                        HandleResult::Single(resp) => {
                            if let Err(e) = framed.send(resp).await {
                                error!("Failed to send response: {}", e);
                                break 'connection_loop;
                            }
                        }
                        HandleResult::Multiple(responses) => {
                            let mut send_failed = false;
                            for resp in responses {
                                if let Err(e) = framed.send(resp).await {
                                    error!("Failed to send response: {}", e);
                                    send_failed = true;
                                    break;
                                }
                            }
                            if send_failed {
                                break 'connection_loop;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    warn!("Connection error from {}: {}", peer_addr, e);
                    break 'connection_loop;
                }
                None => {
                    info!("Connection closed by {}", peer_addr);
                    break 'connection_loop;
                }
            }
        }

        self.sessions.remove_session(session_id);
        info!("Session {} ended", session_id);
    }

    async fn handle_message(&self, session_id: u64, msg: DoipMessage, version: u8) -> HandleResult {
        let payload_type = match msg.payload_type() {
            Some(pt) => pt,
            None => return HandleResult::None,
        };

        match payload_type {
            PayloadType::RoutingActivationRequest => {
                self.handle_routing_activation(session_id, msg.payload, version)
                    .await
            }
            PayloadType::DiagnosticMessage => {
                self.handle_diagnostic_message(session_id, msg.payload, version)
                    .await
            }
            PayloadType::AliveCheckResponse => {
                self.handle_alive_check_response(session_id, msg.payload)
                    .await
            }
            _ => {
                debug!("Unhandled payload type: {:?}", payload_type);
                HandleResult::None
            }
        }
    }

    /// Create a DoIP message with the specified protocol version
    fn create_message(
        &self,
        version: u8,
        payload_type: PayloadType,
        payload: Bytes,
    ) -> DoipMessage {
        DoipMessage::with_version(version, payload_type, payload)
    }

    async fn handle_routing_activation(
        &self,
        session_id: u64,
        payload: Bytes,
        version: u8,
    ) -> HandleResult {
        let request = match routing_activation::Request::parse(&payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid routing activation request: {}", e);
                return HandleResult::None;
            }
        };

        debug!(
            "Routing activation from tester 0x{:04X}",
            request.source_address
        );

        // Check if tester is already registered on another socket
        let response_code = if self.sessions.is_tester_registered(request.source_address) {
            let session = match self.sessions.get_session(session_id) {
                Some(s) => s,
                None => return HandleResult::None,
            };
            if session.tester_address == request.source_address {
                routing_activation::ResponseCode::SourceAddressAlreadyActive
            } else {
                routing_activation::ResponseCode::DifferentSourceAddress
            }
        } else if let Some(code) = request.validate() {
            code
        } else {
            // Activate the session
            self.sessions.update_session(session_id, |s| {
                s.activate_routing(request.source_address);
            });
            routing_activation::ResponseCode::SuccessfullyActivated
        };

        let response = routing_activation::Response {
            tester_address: request.source_address,
            entity_address: self.config.logical_address,
            response_code,
            reserved: 0,
            oem_specific: None,
        };

        info!(
            "Routing activation response: {:?} for tester 0x{:04X}",
            response_code, request.source_address
        );

        HandleResult::Single(self.create_message(
            version,
            PayloadType::RoutingActivationResponse,
            response.to_bytes(),
        ))
    }

    async fn handle_diagnostic_message(
        &self,
        session_id: u64,
        payload: Bytes,
        version: u8,
    ) -> HandleResult {
        let session = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => {
                warn!("Session not found for diagnostic message");
                return self.build_diag_nack(
                    0,
                    diagnostic_message::NackCode::InvalidSourceAddress,
                    version,
                );
            }
        };

        // Check routing is active
        if !session.is_routing_active() {
            warn!("Diagnostic message received before routing activation");
            return self.build_diag_nack(
                session.tester_address,
                diagnostic_message::NackCode::InvalidSourceAddress,
                version,
            );
        }

        let msg = match diagnostic_message::Message::parse(&payload) {
            Ok(m) => m,
            Err(e) => {
                warn!("Invalid diagnostic message: {}", e);
                return self.build_diag_nack(
                    session.tester_address,
                    diagnostic_message::NackCode::TransportProtocolError,
                    version,
                );
            }
        };

        debug!(
            "Diagnostic message: SA=0x{:04X} TA=0x{:04X} SID=0x{:02X}",
            msg.source_address,
            msg.target_address,
            msg.service_id().unwrap_or(0)
        );

        // Build Positive ACK first (0x8002)
        // Per spec: Source and target are swapped from the request
        let ack = diagnostic_message::PositiveAck::new(
            self.config.logical_address, // Server address as source
            msg.source_address,          // Client address as target (swapped)
        );
        let ack_msg = self.create_message(
            version,
            PayloadType::DiagnosticMessagePositiveAck,
            ack.to_bytes(),
        );
        info!("Sending Diagnostic Message Positive ACK (0x8002)");

        // Delegate UDS processing to handler
        let uds_request = UdsRequest::new(
            msg.source_address,
            msg.target_address,
            msg.user_data.clone(),
        );
        let uds_response = self.uds_handler.handle(uds_request);

        // Wrap UDS response in DoIP diagnostic message (0x8001)
        // Per spec: Source and target are swapped from the request
        let diag_response = diagnostic_message::Message::new(
            self.config.logical_address, // Server address as source
            msg.source_address,          // Client address as target (swapped)
            uds_response.payload,
        );
        let response_msg = self.create_message(
            version,
            PayloadType::DiagnosticMessage,
            diag_response.to_bytes(),
        );
        info!("Sending Diagnostic Message Response (0x8001)");

        // Return both: ACK first, then Response
        HandleResult::Multiple(vec![ack_msg, response_msg])
    }

    fn build_diag_nack(
        &self,
        tester_address: u16,
        code: diagnostic_message::NackCode,
        version: u8,
    ) -> HandleResult {
        let nack =
            diagnostic_message::NegativeAck::new(self.config.logical_address, tester_address, code);
        HandleResult::Single(self.create_message(
            version,
            PayloadType::DiagnosticMessageNegativeAck,
            nack.to_bytes(),
        ))
    }

    async fn handle_alive_check_response(&self, session_id: u64, payload: Bytes) -> HandleResult {
        let response = match alive_check::Response::parse(&payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid alive check response: {}", e);
                return HandleResult::None;
            }
        };

        debug!(
            "Alive check response from session {}: tester 0x{:04X}",
            session_id, response.source_address
        );

        HandleResult::None // No response needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, Bytes, BytesMut};
    use std::net::SocketAddr;

    use crate::doip::{diagnostic_message, routing_activation};
    use crate::uds::dummy_handler::DummyEcuHandler;

    fn make_handler() -> (
        TcpHandler<DummyEcuHandler>,
        Arc<SessionManager>,
        Arc<ServerConfig>,
    ) {
        let config = Arc::new(ServerConfig::default());
        let sessions = SessionManager::new();
        let uds_handler = Arc::new(DummyEcuHandler::new());

        (
            TcpHandler::new(config.clone(), sessions.clone(), uds_handler),
            sessions,
            config,
        )
    }

    fn create_session(sessions: &Arc<SessionManager>) -> u64 {
        let addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        sessions.create_session(addr).id
    }

    fn routing_activation_payload(source_address: u16) -> Bytes {
        let mut buf = BytesMut::with_capacity(routing_activation::Request::MIN_LEN);
        buf.put_u16(source_address);
        buf.put_u8(0x00);
        buf.put_u32(0);
        buf.freeze()
    }

    #[tokio::test]
    async fn routing_activation_success_updates_session() {
        let (handler, sessions, config) = make_handler();
        let session_id = create_session(&sessions);

        let payload = routing_activation_payload(0x0E00);
        let result = handler
            .handle_routing_activation(session_id, payload, 0x02)
            .await;

        match result {
            HandleResult::Single(msg) => {
                assert_eq!(
                    msg.payload_type(),
                    Some(PayloadType::RoutingActivationResponse)
                );
                assert_eq!(msg.header.version, 0x02);

                let response = routing_activation::Response::parse(&msg.payload)
                    .expect("valid routing activation response");
                assert_eq!(
                    response.response_code,
                    routing_activation::ResponseCode::SuccessfullyActivated
                );
                assert_eq!(response.entity_address, config.logical_address);
                assert_eq!(response.tester_address, 0x0E00);
            }
            _ => panic!("expected single routing activation response"),
        }

        let session = sessions.get_session(session_id).expect("session exists");
        assert!(session.is_routing_active());
        assert_eq!(session.tester_address, 0x0E00);
    }

    #[tokio::test]
    async fn diagnostic_message_without_routing_returns_nack() {
        let (handler, sessions, config) = make_handler();
        let session_id = create_session(&sessions);

        let uds_payload = Bytes::from(vec![0x10, 0x01]);
        let diag = diagnostic_message::Message::new(0x0E00, config.logical_address, uds_payload);

        let result = handler
            .handle_diagnostic_message(session_id, diag.to_bytes(), 0x03)
            .await;

        match result {
            HandleResult::Single(msg) => {
                assert_eq!(
                    msg.payload_type(),
                    Some(PayloadType::DiagnosticMessageNegativeAck)
                );
                assert_eq!(msg.header.version, 0x03);

                let nack = diagnostic_message::NegativeAck::parse(&msg.payload)
                    .expect("valid diagnostic nack");
                assert_eq!(
                    nack.nack_code,
                    diagnostic_message::NackCode::InvalidSourceAddress
                );
                assert_eq!(nack.source_address, config.logical_address);
                assert_eq!(nack.target_address, 0x0000);
            }
            _ => panic!("expected diagnostic nack response"),
        }
    }

    #[tokio::test]
    async fn diagnostic_message_with_routing_returns_ack_and_response() {
        let (handler, sessions, config) = make_handler();
        let session_id = create_session(&sessions);

        sessions.update_session(session_id, |s| s.activate_routing(0x0E00));

        let uds_payload = Bytes::from(vec![0x10, 0x02]);
        let diag = diagnostic_message::Message::new(0x0E00, config.logical_address, uds_payload);

        let result = handler
            .handle_diagnostic_message(session_id, diag.to_bytes(), 0x02)
            .await;

        match result {
            HandleResult::Multiple(msgs) => {
                assert_eq!(msgs.len(), 2);

                assert_eq!(
                    msgs[0].payload_type(),
                    Some(PayloadType::DiagnosticMessagePositiveAck)
                );
                assert_eq!(msgs[0].header.version, 0x02);

                let ack = diagnostic_message::PositiveAck::parse(&msgs[0].payload)
                    .expect("valid diagnostic ack");
                assert_eq!(ack.source_address, config.logical_address);
                assert_eq!(ack.target_address, 0x0E00);

                assert_eq!(msgs[1].payload_type(), Some(PayloadType::DiagnosticMessage));
                assert_eq!(msgs[1].header.version, 0x02);

                let response = diagnostic_message::Message::parse(&msgs[1].payload)
                    .expect("valid diagnostic response");
                assert_eq!(response.source_address, config.logical_address);
                assert_eq!(response.target_address, 0x0E00);
                assert_eq!(response.user_data.as_ref(), &[0x50, 0x02]);
            }
            _ => panic!("expected ack and diagnostic response"),
        }
    }
}
