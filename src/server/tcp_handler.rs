//! TCP connection handler

use std::sync::Arc;
use bytes::Bytes;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{SinkExt, StreamExt};
use tracing::{info, warn, error, debug};

use crate::doip::{
    DoipCodec, DoipMessage, PayloadType,
    routing_activation, diagnostic_message, alive_check,
};
use crate::server::{ServerConfig, SessionManager};
use crate::uds::{UdsHandler, UdsRequest};

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
        Self { config, sessions, uds_handler }
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

        loop {
            match framed.next().await {
                Some(Ok(msg)) => {
                    debug!("Received message: {:?}", msg.header);

                    let response = self.handle_message(session_id, msg).await;
                    if let Some(resp) = response {
                        if let Err(e) = framed.send(resp).await {
                            error!("Failed to send response: {}", e);
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    warn!("Connection error from {}: {}", peer_addr, e);
                    break;
                }
                None => {
                    info!("Connection closed by {}", peer_addr);
                    break;
                }
            }
        }

        self.sessions.remove_session(session_id);
        info!("Session {} ended", session_id);
    }

    async fn handle_message(&self, session_id: u64, msg: DoipMessage) -> Option<DoipMessage> {
        let payload_type = msg.payload_type()?;

        match payload_type {
            PayloadType::RoutingActivationRequest => {
                self.handle_routing_activation(session_id, msg.payload).await
            }
            PayloadType::DiagnosticMessage => {
                self.handle_diagnostic_message(session_id, msg.payload).await
            }
            PayloadType::AliveCheckResponse => {
                self.handle_alive_check_response(session_id, msg.payload).await
            }
            _ => {
                debug!("Unhandled payload type: {:?}", payload_type);
                None
            }
        }
    }

    async fn handle_routing_activation(
        &self,
        session_id: u64,
        payload: Bytes,
    ) -> Option<DoipMessage> {
        let request = match routing_activation::Request::parse(&payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid routing activation request: {}", e);
                return None;
            }
        };

        debug!("Routing activation from tester 0x{:04X}", request.source_address);

        // Check if tester is already registered on another socket
        let response_code = if self.sessions.is_tester_registered(request.source_address) {
            let session = self.sessions.get_session(session_id)?;
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

        Some(DoipMessage::new(
            PayloadType::RoutingActivationResponse,
            response.to_bytes(),
        ))
    }

    async fn handle_diagnostic_message(
        &self,
        session_id: u64,
        payload: Bytes,
    ) -> Option<DoipMessage> {
        let session = match self.sessions.get_session(session_id) {
            Some(s) => s,
            None => {
                warn!("Session not found for diagnostic message");
                return self.build_diag_nack(0, diagnostic_message::NackCode::InvalidSourceAddress);
            }
        };

        // Check routing is active
        if !session.is_routing_active() {
            warn!("Diagnostic message received before routing activation");
            return self.build_diag_nack(
                session.tester_address,
                diagnostic_message::NackCode::InvalidSourceAddress,
            );
        }

        let msg = match diagnostic_message::Message::parse(&payload) {
            Ok(m) => m,
            Err(e) => {
                warn!("Invalid diagnostic message: {}", e);
                return self.build_diag_nack(
                    session.tester_address,
                    diagnostic_message::NackCode::TransportProtocolError,
                );
            }
        };

        debug!(
            "Diagnostic message: SA=0x{:04X} TA=0x{:04X} SID=0x{:02X}",
            msg.source_address,
            msg.target_address,
            msg.service_id().unwrap_or(0)
        );

        // Delegate UDS processing to handler
        let uds_request = UdsRequest::new(
            msg.source_address,
            msg.target_address,
            msg.user_data.clone(),
        );
        let uds_response = self.uds_handler.handle(uds_request);

        // Wrap UDS response in DoIP diagnostic message
        let diag_response = diagnostic_message::Message::new(
            uds_response.source_address,
            uds_response.target_address,
            uds_response.data,
        );

        Some(DoipMessage::new(
            PayloadType::DiagnosticMessage,
            diag_response.to_bytes(),
        ))
    }

    fn build_diag_nack(
        &self,
        tester_address: u16,
        code: diagnostic_message::NackCode,
    ) -> Option<DoipMessage> {
        let nack = diagnostic_message::NegativeAck::new(
            self.config.logical_address,
            tester_address,
            code,
        );
        Some(DoipMessage::new(
            PayloadType::DiagnosticMessageNegativeAck,
            nack.to_bytes(),
        ))
    }

    async fn handle_alive_check_response(
        &self,
        session_id: u64,
        payload: Bytes,
    ) -> Option<DoipMessage> {
        let response = match alive_check::Response::parse(&payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("Invalid alive check response: {}", e);
                return None;
            }
        };

        debug!(
            "Alive check response from session {}: tester 0x{:04X}",
            session_id, response.source_address
        );

        None // No response needed
    }
}
