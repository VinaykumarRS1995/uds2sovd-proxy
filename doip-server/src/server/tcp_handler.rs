/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! TCP Diagnostic Handler (ISO 13400-2:2019 Section 8.4)
//!
//! Accepts diagnostic TCP connections on the DoIP port, manages the per-connection
//! lifecycle, and dispatches incoming messages:
//!
//! | Incoming payload type | State required | Action |
//! |---|---|---|
//! | `0x0005` [`RoutingActivationRequest`] | Connected | Activate or deny routing |
//! | `0x8001` [`DiagnosticMessage`] | RoutingActive | Dispatch to [`UdsHandler`], send Ack + response |
//! | `0x0007` [`AliveCheckRequest`] | Any | Send [`AliveCheckResponse`] |
//! | anything else | – | Send [`GenericNack`] and close |
//!
//! [`RoutingActivationRequest`]: crate::doip::routing_activation::Request
//! [`DiagnosticMessage`]: crate::doip::diagnostic_message::Message
//! [`AliveCheckRequest`]: crate::doip::alive_check::Request
//! [`AliveCheckResponse`]: crate::doip::alive_check::Response
//! [`GenericNack`]: crate::doip::header::GenericNackCode
//! [`UdsHandler`]: crate::uds::UdsHandler

use std::sync::Arc;

use bytes::Bytes;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::{
    doip::{
        DoipMessage, DoipParseable, DoipSerializable, alive_check,
        codec::DoipCodec,
        diagnostic_message::{self, DiagnosticAck, DiagnosticNackCode},
        header::{GenericNackCode, PayloadType},
        payload::DoipPayload,
        routing_activation::{self, ActivationResponseCode},
    },
    server::{
        ServerConfig, SessionManager,
        session::{Session, SessionId},
    },
    uds::{UdsHandler, UdsRequest},
};

use bytes::BytesMut;
use futures_util::{SinkExt as _, StreamExt as _};

/// Run the TCP diagnostic listener.
///
/// Binds to `config.tcp_addr()`, accepts connections up to `config.max_connections()`,
/// and spawns a task per connection. The caller supplies a `handler` that processes
/// UDS requests; it must be `Clone + Send + Sync + 'static` so it can be shared across
/// connection tasks.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the TCP listener cannot be bound.
pub async fn run<H>(
    config: Arc<ServerConfig>,
    sessions: Arc<SessionManager>,
    handler: H,
) -> std::io::Result<()>
where
    H: UdsHandler + Clone + 'static,
{
    let listener = TcpListener::bind(config.tcp_addr()).await?;
    info!(addr = %config.tcp_addr(), "DoIP TCP handler listening");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "TCP accept failed");
                continue;
            }
        };

        if sessions.session_count() >= config.max_connections() {
            warn!(peer = %peer_addr, max = config.max_connections(), "max connections reached, dropping");
            continue;
        }

        let config = Arc::clone(&config);
        let sessions = Arc::clone(&sessions);
        let handler = handler.clone();

        tokio::spawn(async move {
            handle_connection(stream, peer_addr, config, sessions, handler).await;
        });
    }
}

/// Drive a single TCP connection through its `DoIP` lifecycle.
pub(crate) async fn handle_connection<H>(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    config: Arc<ServerConfig>,
    sessions: Arc<SessionManager>,
    handler: H,
) where
    H: UdsHandler,
{
    let session = sessions.create_session(peer_addr);
    let session_id = session.id();
    info!(session_id = ?session_id, peer = %peer_addr, "DoIP TCP connection established");

    let initial_timeout = Duration::from_millis(config.initial_inactivity_timeout_ms());
    let general_timeout = Duration::from_millis(config.general_inactivity_timeout_ms());

    let mut framed = Framed::new(stream, DoipCodec::default());

    // ISO 13400-2:2019 §8.4.2 — apply T_TCP_Initial on the first message.
    let first_msg = match timeout(initial_timeout, framed.next()).await {
        Ok(Some(Ok(msg))) => msg,
        Ok(Some(Err(e))) => {
            warn!(session_id = ?session_id, peer = %peer_addr, error = %e, "framing error on first message");
            sessions.remove_session(session_id);
            return;
        }
        Ok(None) => {
            debug!(session_id = ?session_id, peer = %peer_addr, "connection closed before first message");
            sessions.remove_session(session_id);
            return;
        }
        Err(_) => {
            warn!(session_id = ?session_id, peer = %peer_addr, "T_TCP_Initial timeout, closing");
            sessions.remove_session(session_id);
            return;
        }
    };

    // The first message MUST be a Routing Activation Request.
    if !matches!(
        first_msg.payload_type(),
        Some(PayloadType::RoutingActivationRequest)
    ) {
        warn!(session_id = ?session_id, peer = %peer_addr, "first message is not RoutingActivationRequest, closing");
        send_generic_nack(
            &mut framed,
            first_msg.header().version(),
            GenericNackCode::InvalidPayloadLength,
        )
        .await;
        sessions.remove_session(session_id);
        return;
    }

    let version = first_msg.header().version();
    if !process_routing_activation(
        &mut framed,
        &sessions,
        session_id,
        first_msg,
        &config,
        version,
    )
    .await
    {
        sessions.remove_session(session_id);
        return;
    }

    // Main message loop with T_TCP_General timeout per ISO 13400-2:2019 §8.4.3.
    loop {
        let msg = match timeout(general_timeout, framed.next()).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => {
                warn!(session_id = ?session_id, peer = %peer_addr, error = %e, "framing error");
                break;
            }
            Ok(None) => {
                debug!(session_id = ?session_id, peer = %peer_addr, "connection closed by tester");
                break;
            }
            Err(_) => {
                warn!(session_id = ?session_id, peer = %peer_addr, "T_TCP_General inactivity timeout, closing");
                break;
            }
        };

        let ver = msg.header().version();
        match DoipPayload::parse(&msg) {
            Ok(payload) => {
                let keep_open = dispatch(
                    &mut framed,
                    &sessions,
                    session_id,
                    payload,
                    ver,
                    &handler,
                    &config,
                )
                .await;
                if !keep_open {
                    break;
                }
            }
            Err(e) => {
                warn!(session_id = ?session_id, error = %e, "unknown payload type");
                send_generic_nack(&mut framed, ver, GenericNackCode::UnknownPayloadType).await;
                break;
            }
        }
    }

    sessions.remove_session(session_id);
    info!(session_id = ?session_id, peer = %peer_addr, "DoIP TCP connection closed");
}

/// Handle a Routing Activation Request.  Returns `true` if activation succeeded.
async fn process_routing_activation(
    framed: &mut Framed<TcpStream, DoipCodec>,
    sessions: &Arc<SessionManager>,
    session_id: SessionId,
    msg: DoipMessage,
    config: &ServerConfig,
    version: u8,
) -> bool {
    let req = match routing_activation::RoutingActivationRequest::parse(msg.payload()) {
        Ok(r) => r,
        Err(e) => {
            warn!(session_id = ?session_id, error = %e, "failed to parse RoutingActivationRequest");
            send_generic_nack(framed, version, GenericNackCode::InvalidPayloadLength).await;
            return false;
        }
    };

    // Deny if the tester logical address is already active on another socket.
    if sessions.is_tester_registered(req.source_address()) {
        warn!(
            session_id = ?session_id,
            tester_address = req.source_address(),
            "tester already registered"
        );
        let denial = routing_activation::RoutingActivationResponse::denial(
            req.source_address(),
            config.logical_address(),
            ActivationResponseCode::SourceAddressAlreadyActive,
        );
        send_serializable(
            framed,
            version,
            PayloadType::RoutingActivationResponse,
            &denial,
        )
        .await;
        return false;
    }

    // Activate routing for this session.
    sessions.update_session(session_id, |s| s.activate_routing(req.source_address()));
    info!(
        session_id = ?session_id,
        tester_address = req.source_address(),
        "routing activated"
    );

    let response = routing_activation::RoutingActivationResponse::success(
        req.source_address(),
        config.logical_address(),
    );
    send_serializable(
        framed,
        version,
        PayloadType::RoutingActivationResponse,
        &response,
    )
    .await;
    true
}

/// Dispatch a parsed `DoIP` payload inside the main loop.  Returns `true` to keep connection open.
async fn dispatch<H>(
    framed: &mut Framed<TcpStream, DoipCodec>,
    sessions: &Arc<SessionManager>,
    session_id: SessionId,
    payload: DoipPayload,
    version: u8,
    handler: &H,
    config: &ServerConfig,
) -> bool
where
    H: UdsHandler,
{
    match payload {
        DoipPayload::AliveCheckRequest(_) => {
            debug!(session_id = ?session_id, "AliveCheckRequest received");
            let session = sessions.get_session(session_id);
            let source = session.map_or(config.logical_address(), |s| s.tester_address());
            let resp = alive_check::AliveCheckResponse::new(source);
            send_serializable(framed, version, PayloadType::AliveCheckResponse, &resp).await;
            true
        }

        DoipPayload::DiagnosticMessage(diag) => {
            // Routing must be active before diagnostic messages are accepted.
            let session = sessions.get_session(session_id);
            let routing_active = session.as_ref().is_some_and(Session::is_routing_active);

            if !routing_active {
                warn!(
                    session_id = ?session_id,
                    "DiagnosticMessage received before routing activation"
                );
                let nack = DiagnosticAck::negative(
                    diag.source_address(),
                    diag.target_address(),
                    DiagnosticNackCode::InvalidSourceAddress,
                );
                send_serializable(
                    framed,
                    version,
                    PayloadType::DiagnosticMessageNegativeAck,
                    &nack,
                )
                .await;
                return false;
            }

            // Send positive ack immediately per ISO 13400-2:2019 §8.4.4.
            let ack = DiagnosticAck::positive(diag.source_address(), diag.target_address());
            send_serializable(
                framed,
                version,
                PayloadType::DiagnosticMessagePositiveAck,
                &ack,
            )
            .await;

            // Dispatch to UDS handler.
            let uds_req = UdsRequest::new(
                diag.source_address(),
                diag.target_address(),
                diag.user_data().clone(),
            );
            let uds_resp = match handler.handle(uds_req).await {
                Ok(r) => r,
                Err(e) => {
                    error!(session_id = ?session_id, error = %e, "UDS handler error");
                    let nack = DiagnosticAck::negative(
                        diag.source_address(),
                        diag.target_address(),
                        DiagnosticNackCode::TargetUnreachable,
                    );
                    send_serializable(
                        framed,
                        version,
                        PayloadType::DiagnosticMessageNegativeAck,
                        &nack,
                    )
                    .await;
                    return false;
                }
            };

            // Wrap UDS response in a DoIP DiagnosticMessage.
            let resp_diag = match diagnostic_message::DiagnosticMessage::new(
                uds_resp.source_address(),
                uds_resp.target_address(),
                uds_resp.payload().clone(),
            ) {
                Ok(m) => m,
                Err(e) => {
                    error!(session_id = ?session_id, error = %e, "failed to build DiagnosticMessage response");
                    return false;
                }
            };
            send_serializable(framed, version, PayloadType::DiagnosticMessage, &resp_diag).await;
            true
        }

        DoipPayload::RoutingActivationRequest(_) => {
            // Routing activation in the main loop means the tester is re-activating.
            // Per ISO 13400-2:2019, treat as protocol error after initial activation.
            warn!(
                session_id = ?session_id,
                "unexpected RoutingActivationRequest after activation"
            );
            send_generic_nack(framed, version, GenericNackCode::InvalidPayloadLength).await;
            false
        }

        other => {
            warn!(session_id = ?session_id, payload_type = ?other.payload_type(), "unexpected payload type, closing");
            send_generic_nack(framed, version, GenericNackCode::UnknownPayloadType).await;
            false
        }
    }
}

/// Encode a serializable `DoIP` payload into a [`DoipMessage`] and send it.
async fn send_serializable<T: DoipSerializable>(
    framed: &mut Framed<TcpStream, DoipCodec>,
    version: u8,
    payload_type: PayloadType,
    body: &T,
) {
    let mut buf = BytesMut::new();
    body.write_to(&mut buf);
    let msg = DoipMessage::with_version(version, payload_type, buf.freeze());
    if let Err(e) = framed.send(msg).await {
        error!(error = %e, "failed to send DoIP message");
    }
}

/// Send a Generic NACK message and flush.
async fn send_generic_nack(
    framed: &mut Framed<TcpStream, DoipCodec>,
    version: u8,
    code: GenericNackCode,
) {
    let msg = DoipMessage::with_version(
        version,
        PayloadType::GenericNack,
        Bytes::copy_from_slice(&[code as u8]),
    );
    if let Err(e) = framed.send(msg).await {
        error!(error = %e, "failed to send GenericNack");
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::BytesMut;
    use tokio::io::AsyncWriteExt as _;
    use tokio_util::codec::{Decoder, Encoder};

    use crate::{
        doip::{
            DoipParseable as _, DoipSerializable, alive_check,
            codec::DoipCodec,
            diagnostic_message::{self, DiagnosticNackCode},
            header::{DEFAULT_PROTOCOL_VERSION, DOIP_HEADER_VERSION_MASK, PayloadType},
            routing_activation::{self, ActivationResponseCode},
        },
        server::{ServerConfig, SessionManager},
        uds::{UdsHandler, UdsRequest, UdsResponse},
    };

    // ── helpers ─────────────────────────────────────────────────────────────

    /// A stub UDS handler that echoes the request payload back as the response.
    #[derive(Clone)]
    struct EchoHandler;
    impl UdsHandler for EchoHandler {
        fn handle(
            &self,
            req: UdsRequest,
        ) -> impl std::future::Future<Output = crate::Result<UdsResponse>> + Send {
            std::future::ready(Ok(UdsResponse::new(
                req.target_address(),
                req.source_address(),
                req.payload().clone(),
            )))
        }
    }

    /// Tester logical address used across tests (arbitrary, non-zero, non-broadcast)
    const TESTER_ADDR: u16 = 0x0E80;
    /// Entity logical address used across tests
    const ENTITY_ADDR: u16 = 0xE000;
    /// An address that is never registered — used to verify negative checks
    const OTHER_ADDR: u16 = 0x0E81;
    /// DoIP header length (8 bytes per ISO 13400-2:2019)
    const DOIP_HEADER_LEN: usize = 8;
    /// Read buffer capacity for integration test responses
    const READ_BUF: usize = 256;
    /// Small buffer for single-message responses (e.g. GenericNack)
    const SMALL_BUF: usize = 64;
    /// Milliseconds to wait for the server task to process and respond
    const REPLY_WAIT_MS: u64 = 50;

    const VER: u8 = DEFAULT_PROTOCOL_VERSION;
    const INV: u8 = DEFAULT_PROTOCOL_VERSION ^ DOIP_HEADER_VERSION_MASK;

    /// Build a raw DoIP frame: header (8 bytes) + payload.
    fn make_frame(payload_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(VER);
        buf.push(INV);
        buf.extend_from_slice(&payload_type.to_be_bytes());
        buf.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload fits in u32")
                .to_be_bytes(),
        );
        buf.extend_from_slice(payload);
        buf
    }

    /// Encode a serializable type into a DoIP frame.
    fn encode_payload<T: DoipSerializable>(payload_type: PayloadType, body: &T) -> Vec<u8> {
        let mut buf = BytesMut::new();
        body.write_to(&mut buf);
        make_frame(u16::from(payload_type), &buf)
    }

    /// Decode the next DoIP message from a byte slice.
    fn decode_next(data: &mut BytesMut) -> Option<crate::doip::DoipMessage> {
        DoipCodec::default()
            .decode(data)
            .expect("decode should not error")
    }

    fn config() -> Arc<ServerConfig> {
        let cfg = ServerConfig::new(ENTITY_ADDR).with_addresses(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        Arc::new(cfg)
    }

    // ── integration tests: handle_connection ────────────────────────────────

    /// Spawn a listener, connect a client, pass the server-side stream to
    /// `handle_connection`, and communicate over the client-side stream.
    async fn connect_pair(
        config: Arc<ServerConfig>,
        sessions: Arc<SessionManager>,
    ) -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server_stream, peer_addr) = listener.accept().await.unwrap();
        let handle = tokio::spawn(async move {
            super::handle_connection(server_stream, peer_addr, config, sessions, EchoHandler).await;
        });
        (client, handle)
    }

    #[tokio::test]
    async fn routing_activation_success_and_response() {
        let config = config();
        let sessions = SessionManager::new();
        let (mut client, _handle) = connect_pair(Arc::clone(&config), Arc::clone(&sessions)).await;

        // Send RoutingActivationRequest: source=TESTER_ADDR, type=Default, reserved=0
        let ra_payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&TESTER_ADDR.to_be_bytes());
            p.push(0x00);
            p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            p
        };
        client
            .write_all(&make_frame(
                u16::from(PayloadType::RoutingActivationRequest),
                &ra_payload,
            ))
            .await
            .unwrap();

        let mut buf = BytesMut::with_capacity(READ_BUF);
        tokio::time::sleep(tokio::time::Duration::from_millis(REPLY_WAIT_MS)).await;
        let mut tmp = [0u8; READ_BUF];
        match client.try_read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => {}
        }
        let msg = decode_next(&mut buf).expect("should receive RoutingActivationResponse");
        assert_eq!(
            msg.payload_type(),
            Some(PayloadType::RoutingActivationResponse)
        );
    }

    #[tokio::test]
    async fn first_message_not_routing_activation_gets_nack() {
        let config = config();
        let sessions = SessionManager::new();
        let (mut client, _handle) = connect_pair(Arc::clone(&config), Arc::clone(&sessions)).await;

        // Send AliveCheckRequest as first message — must be rejected.
        client
            .write_all(&make_frame(u16::from(PayloadType::AliveCheckRequest), &[]))
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(REPLY_WAIT_MS)).await;
        let mut buf = BytesMut::with_capacity(SMALL_BUF);
        let mut tmp = [0u8; SMALL_BUF];
        match client.try_read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => {}
        }
        let msg = decode_next(&mut buf).expect("should receive GenericNack");
        assert_eq!(msg.payload_type(), Some(PayloadType::GenericNack));
    }

    #[test]
    fn session_manager_create_remove() {
        let sm = SessionManager::new();
        let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 19999));
        let s = sm.create_session(addr);
        assert_eq!(sm.session_count(), 1);
        sm.remove_session(s.id());
        assert_eq!(sm.session_count(), 0);
    }

    #[test]
    fn session_routing_activation() {
        let sm = SessionManager::new();
        let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 19998));
        let s = sm.create_session(addr);
        assert!(!s.is_routing_active());
        sm.update_session(s.id(), |s| s.activate_routing(TESTER_ADDR));
        let s2 = sm.get_session(s.id()).unwrap();
        assert!(s2.is_routing_active());
        assert_eq!(s2.tester_address(), TESTER_ADDR);
    }

    #[test]
    fn session_tester_already_registered() {
        let sm = SessionManager::new();
        let a1: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 19001));
        let a2: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 19002));
        let s1 = sm.create_session(a1);
        let _s2 = sm.create_session(a2);
        sm.update_session(s1.id(), |s| s.activate_routing(TESTER_ADDR));
        assert!(sm.is_tester_registered(TESTER_ADDR));
        assert!(!sm.is_tester_registered(OTHER_ADDR));
    }

    #[test]
    fn make_frame_produces_valid_doip_header() {
        let frame = make_frame(u16::from(PayloadType::AliveCheckRequest), &[]);
        assert_eq!(frame.len(), DOIP_HEADER_LEN);
        assert_eq!(frame[0], VER);
        assert_eq!(frame[1], INV);
        assert_eq!(
            u16::from_be_bytes([frame[2], frame[3]]),
            u16::from(PayloadType::AliveCheckRequest)
        );
        assert_eq!(
            u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]),
            0
        );
    }

    #[test]
    fn routing_activation_response_success_fields() {
        let resp = routing_activation::RoutingActivationResponse::success(TESTER_ADDR, ENTITY_ADDR);
        assert!(resp.is_success());
        assert_eq!(resp.tester_address(), TESTER_ADDR);
        assert_eq!(resp.entity_address(), ENTITY_ADDR);
    }

    #[test]
    fn routing_activation_response_denial_fields() {
        let resp = routing_activation::RoutingActivationResponse::denial(
            TESTER_ADDR,
            ENTITY_ADDR,
            ActivationResponseCode::SourceAddressAlreadyActive,
        );
        assert!(!resp.is_success());
        assert_eq!(
            resp.response_code(),
            ActivationResponseCode::SourceAddressAlreadyActive
        );
    }

    #[test]
    fn diagnostic_ack_positive_roundtrip() {
        let ack = diagnostic_message::DiagnosticAck::positive(TESTER_ADDR, ENTITY_ADDR);
        assert!(matches!(
            ack.result(),
            crate::doip::diagnostic_message::AckResult::Positive
        ));
        assert_eq!(ack.source_address(), TESTER_ADDR);
    }

    #[test]
    fn diagnostic_ack_negative_fields() {
        let ack = diagnostic_message::DiagnosticAck::negative(
            TESTER_ADDR,
            ENTITY_ADDR,
            DiagnosticNackCode::InvalidSourceAddress,
        );
        assert!(matches!(
            ack.result(),
            crate::doip::diagnostic_message::AckResult::Negative(_)
        ));
    }

    #[test]
    fn alive_check_response_source() {
        let r = alive_check::AliveCheckResponse::new(TESTER_ADDR);
        assert_eq!(r.source_address(), TESTER_ADDR);
    }

    #[test]
    fn encode_payload_routing_activation_response() {
        let resp = routing_activation::RoutingActivationResponse::success(TESTER_ADDR, ENTITY_ADDR);
        let frame = encode_payload(PayloadType::RoutingActivationResponse, &resp);
        assert!(frame.len() >= DOIP_HEADER_LEN);
        let pt = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(pt, u16::from(PayloadType::RoutingActivationResponse));
    }
}
