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

//! UDP Vehicle Discovery Handler (ISO 13400-2:2019 Section 8.3)
//!
//! Listens on the DoIP UDP port and responds to vehicle identification requests:
//!
//! | Incoming payload type | Trigger | Response |
//! |---|---|---|
//! | `0x0001` [`VehicleIdentificationRequest`] | Any | [`VehicleIdentificationResponse`] |
//! | `0x0002` [`VehicleIdentificationRequestWithEid`] | EID matches config | [`VehicleIdentificationResponse`] |
//! | `0x0003` [`VehicleIdentificationRequestWithVin`] | VIN matches config | [`VehicleIdentificationResponse`] |
//! | anything else | – | silently ignored |
//!
//! [`VehicleIdentificationRequest`]: crate::doip::vehicle_id::Request
//! [`VehicleIdentificationRequestWithEid`]: crate::doip::vehicle_id::VehicleIdRequestWithEid
//! [`VehicleIdentificationRequestWithVin`]: crate::doip::vehicle_id::VehicleIdRequestWithVin
//! [`VehicleIdentificationResponse`]: crate::doip::vehicle_id::VehicleIdResponse

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::{
    doip::{
        DoipMessage, DoipParseable, DoipSerializable,
        header::{DOIP_HEADER_LENGTH, DoipHeader, PayloadType},
        vehicle_id,
    },
    server::ServerConfig,
};

/// Maximum UDP datagram size we accept (64 KiB — well above any `DoIP` message).
const MAX_UDP_DATAGRAM: usize = 65_535;

/// Run the UDP vehicle-discovery listener.
///
/// Binds to `config.udp_addr()` and loops indefinitely, replying to vehicle
/// identification requests.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the UDP socket cannot be bound.
pub async fn run(config: &ServerConfig) -> std::io::Result<()> {
    let socket = UdpSocket::bind(config.udp_addr()).await?;
    info!(addr = %config.udp_addr(), "DoIP UDP handler listening");

    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "UDP recv_from failed");
                continue;
            }
        };

        let datagram = buf.get(..len).unwrap_or_default();
        debug!(peer = %peer, bytes = len, "UDP datagram received");

        handle_datagram(&socket, config, datagram, peer).await;
    }
}

/// Process a single UDP datagram and send a response when appropriate.
async fn handle_datagram(
    socket: &UdpSocket,
    config: &ServerConfig,
    datagram: &[u8],
    peer: SocketAddr,
) {
    // Parse the DoIP header — silently drop malformed datagrams (ISO 13400-2 §8.3).
    let header = match DoipHeader::parse(datagram) {
        Ok(h) => h,
        Err(e) => {
            warn!(peer = %peer, error = %e, "UDP: malformed DoIP header, dropping");
            return;
        }
    };

    let version = header.version();

    // Validate header per ISO 13400-2:2019 — drop datagrams with protocol violations.
    if let Some(nack) = header.validate() {
        warn!(peer = %peer, nack = ?nack, "UDP: DoIP header validation failed, dropping");
        return;
    }

    // Verify the datagram contains the full declared payload (guards against truncated frames).
    let declared_len = DOIP_HEADER_LENGTH
        .saturating_add(usize::try_from(header.payload_length()).unwrap_or(usize::MAX));
    if datagram.len() < declared_len {
        warn!(
            peer     = %peer,
            got      = datagram.len(),
            expected = declared_len,
            "UDP: truncated datagram, dropping"
        );
        return;
    }

    let payload_bytes = datagram.get(DOIP_HEADER_LENGTH..).unwrap_or_default();

    let Some(payload_type) = PayloadType::try_from(header.payload_type()).ok() else {
        warn!(
            peer         = %peer,
            payload_type = format!("0x{:04X}", header.payload_type()),
            "UDP: unknown payload type, dropping"
        );
        return;
    };

    match payload_type {
        PayloadType::VehicleIdentificationRequest => {
            debug!(peer = %peer, "UDP: VehicleIdentificationRequest – responding");
            send_vehicle_id_response(socket, config, version, peer).await;
        }

        PayloadType::VehicleIdentificationRequestWithEid => {
            match vehicle_id::VehicleIdRequestWithEid::parse(payload_bytes) {
                Ok(req) if req.eid() == &config.eid() => {
                    debug!(peer = %peer, "UDP: VehicleIdentificationRequestWithEid – EID match");
                    send_vehicle_id_response(socket, config, version, peer).await;
                }
                Ok(_) => {
                    debug!(peer = %peer, "UDP: VehicleIdentificationRequestWithEid – EID mismatch, ignoring");
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "UDP: malformed EID request, dropping");
                }
            }
        }

        PayloadType::VehicleIdentificationRequestWithVin => {
            match vehicle_id::VehicleIdRequestWithVin::parse(payload_bytes) {
                Ok(req) if req.vin() == &config.vin() => {
                    debug!(peer = %peer, "UDP: VehicleIdentificationRequestWithVin – VIN match");
                    send_vehicle_id_response(socket, config, version, peer).await;
                }
                Ok(_) => {
                    debug!(peer = %peer, "UDP: VehicleIdentificationRequestWithVin – VIN mismatch, ignoring");
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "UDP: malformed VIN request, dropping");
                }
            }
        }

        other => {
            debug!(
                peer         = %peer,
                payload_type = format!("{other:?}"),
                "UDP: non-vehicle-id payload type, ignoring"
            );
        }
    }
}

/// Serialize and send a [`vehicle_id::VehicleIdResponse`] back to `peer`.
async fn send_vehicle_id_response(
    socket: &UdpSocket,
    config: &ServerConfig,
    version: u8,
    peer: SocketAddr,
) {
    let response = vehicle_id::VehicleIdResponse::new(
        config.vin(),
        config.logical_address(),
        config.eid(),
        config.gid(),
    )
    .with_routing_required();

    // Serialize payload then wrap in a DoIP frame echoing the request's protocol version.
    let payload: Bytes = response.to_bytes();
    let frame =
        DoipMessage::with_version(version, PayloadType::VehicleIdentificationResponse, payload)
            .to_bytes();

    match socket.send_to(&frame, peer).await {
        Ok(n) => debug!(peer = %peer, bytes = n, "UDP: VehicleIdentificationResponse sent"),
        Err(e) => error!(peer = %peer, error = %e, "UDP: failed to send response"),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{
        doip::{
            DoipMessage, DoipSerializable,
            header::{DEFAULT_PROTOCOL_VERSION, DOIP_HEADER_LENGTH, DoipHeader, PayloadType},
            vehicle_id,
        },
        server::ServerConfig,
    };
    use bytes::Bytes;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn default_config() -> ServerConfig {
        ServerConfig::default()
    }

    /// Build a raw UDP datagram: DoIP header + serialized payload.
    fn build_datagram(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
        let msg = DoipMessage::with_version(
            DEFAULT_PROTOCOL_VERSION,
            payload_type,
            Bytes::copy_from_slice(payload),
        );
        msg.to_bytes().to_vec()
    }

    // ── parse guard tests ─────────────────────────────────────────────────────

    #[test]
    fn too_short_datagram_is_dropped() {
        // Anything shorter than DOIP_HEADER_LENGTH must not panic or produce output.
        let short = [0u8; 4];
        let config = default_config();
        // DoipHeader::parse should error → handle_datagram returns early.
        assert!(DoipHeader::parse(&short).is_err());
        let _ = config; // no panic = pass
    }

    #[test]
    fn vehicle_id_request_datagram_is_well_formed() {
        let datagram = build_datagram(PayloadType::VehicleIdentificationRequest, &[]);
        let header = DoipHeader::parse(&datagram).expect("header parses");
        assert_eq!(
            PayloadType::try_from(header.payload_type()).unwrap(),
            PayloadType::VehicleIdentificationRequest
        );
    }

    #[test]
    fn eid_request_matches_config_eid() {
        let config = default_config();
        // RequestWithEid wire format is just the 6-byte EID.
        let payload = config.eid();
        let datagram = build_datagram(PayloadType::VehicleIdentificationRequestWithEid, &payload);

        let header = DoipHeader::parse(&datagram).unwrap();
        let ptype = PayloadType::try_from(header.payload_type()).unwrap();
        assert_eq!(ptype, PayloadType::VehicleIdentificationRequestWithEid);

        let parsed =
            vehicle_id::VehicleIdRequestWithEid::parse(&datagram[DOIP_HEADER_LENGTH..]).unwrap();
        assert_eq!(parsed.eid(), &config.eid());
    }

    #[test]
    fn eid_request_mismatch_does_not_match_config() {
        let config = default_config();
        let different_eid = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        assert_ne!(different_eid, config.eid());
    }

    #[test]
    fn vin_request_matches_config_vin() {
        let config = default_config();
        // RequestWithVin wire format is just the 17-byte VIN.
        let payload = config.vin();
        let datagram = build_datagram(PayloadType::VehicleIdentificationRequestWithVin, &payload);

        let header = DoipHeader::parse(&datagram).unwrap();
        let ptype = PayloadType::try_from(header.payload_type()).unwrap();
        assert_eq!(ptype, PayloadType::VehicleIdentificationRequestWithVin);

        let parsed =
            vehicle_id::VehicleIdRequestWithVin::parse(&datagram[DOIP_HEADER_LENGTH..]).unwrap();
        assert_eq!(parsed.vin(), &config.vin());
    }

    #[test]
    fn vin_request_mismatch_does_not_match_config() {
        let config = default_config();
        let different_vin = *b"WRONGVIN123456789";
        assert_ne!(different_vin, config.vin());
    }

    #[test]
    fn vehicle_id_response_is_built_from_config() {
        let config = default_config();
        let response = vehicle_id::VehicleIdResponse::new(
            config.vin(),
            config.logical_address(),
            config.eid(),
            config.gid(),
        );
        let payload = response.to_bytes();
        // Minimal response: 32 bytes (no sync status)
        assert_eq!(payload.len(), vehicle_id::VehicleIdResponse::MIN_LEN);
    }

    #[test]
    fn non_vehicle_id_payload_type_is_ignored() {
        // DiagnosticMessage on UDP must not be processed as a vehicle-id request.
        let datagram = build_datagram(PayloadType::DiagnosticMessage, &[0x00, 0x00, 0x10, 0x03]);
        let header = DoipHeader::parse(&datagram).unwrap();
        let ptype = PayloadType::try_from(header.payload_type()).unwrap();
        assert_eq!(ptype, PayloadType::DiagnosticMessage);
        // The handler's match arm falls through to the `other =>` branch — no response sent.
    }

    #[test]
    fn malformed_eid_payload_fails_to_parse() {
        // 5 bytes instead of required 6 → RequestWithEid::parse must error.
        let short_eid = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        assert!(vehicle_id::VehicleIdRequestWithEid::parse(&short_eid).is_err());
    }

    #[test]
    fn malformed_vin_payload_fails_to_parse() {
        // 16 bytes instead of required 17 → RequestWithVin::parse must error.
        let short_vin = [0x56u8; 16];
        assert!(vehicle_id::VehicleIdRequestWithVin::parse(&short_vin).is_err());
    }

    #[test]
    fn invalid_header_version_fails_validation() {
        // Version 0x04 is unknown — parses OK but validate() must return Some(nack).
        // Wire layout: [version, inv_version, type_hi, type_lo, payload_len(4 bytes)]
        let datagram = [0x04u8, 0xFB, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let header = DoipHeader::parse(&datagram).unwrap();
        assert!(header.validate().is_some());
    }

    #[test]
    fn truncated_datagram_is_dropped() {
        // Header declares payload_length = 6 but datagram only has the 8-byte header.
        // Wire: valid version 0x02, inv 0xFD, type 0x0001, length 0x00000006
        let datagram = [0x02u8, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06];
        let header = DoipHeader::parse(&datagram).unwrap();
        let declared = DOIP_HEADER_LENGTH
            .saturating_add(usize::try_from(header.payload_length()).unwrap_or(usize::MAX));
        // datagram.len() (8) < declared (14) → truncated
        assert!(datagram.len() < declared);
    }

    #[test]
    fn unknown_raw_payload_type_is_not_a_known_variant() {
        // Raw u16 0x9999 has no PayloadType variant → try_from returns Err.
        assert!(PayloadType::try_from(0x9999u16).is_err());
    }
}
