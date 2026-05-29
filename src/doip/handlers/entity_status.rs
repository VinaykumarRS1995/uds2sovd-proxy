/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use crate::doip::{
    PayloadHandler,
    constants::{DOIP_NODE_TYPE, ENTITY_STATUS_RESPONSE_LEN},
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
};

// DoipEntityStatusRequest (0x4001)

/// Handles DoipEntityStatusRequest (ISO 13400-2 §7.6.3).
/// Reports node type, max TCP sessions, current sessions, and max data size.
pub struct EntityStatusHandler {
    max_connections: u8,
    // TODO: Derive max_data_size from config instead of hardcoding at registration.
    max_data_size: u32,
}

impl EntityStatusHandler {
    pub fn new(max_connections: u8, max_data_size: u32) -> Self {
        Self {
            max_connections,
            max_data_size,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for EntityStatusHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::DoipEntityStatusRequest
    }

    /// Response payload (7 bytes):
    /// [0]     node type (0x01 = DoIP node)
    /// [1]     max concurrent TCP sockets
    /// [2]     currently open TCP sockets (0 — not tracked at this level)
    /// [3..7]  max data size (u32 big-endian)
    fn handle(&self, udp_request: UdpRequest) -> Result<Response, Error> {
        if !udp_request.payload().is_empty() {
            return Err(Error::InvalidPayloadLength {
                declared: udp_request.payload().len() as u32,
                actual: udp_request.payload().len(),
            });
        }
        let mut payload = Vec::with_capacity(ENTITY_STATUS_RESPONSE_LEN);
        payload.push(DOIP_NODE_TYPE);
        payload.push(self.max_connections);
        payload.push(0x00); // current sessions — not tracked at this level
        payload.extend_from_slice(&self.max_data_size.to_be_bytes());
        Ok(Response::new(
            UdpPayloadType::DoipEntityStatusResponse as u16,
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_returns_7_byte_status_response() {
        let handler = EntityStatusHandler::new(10, 65_535);
        let req = UdpRequest::new(UdpPayloadType::DoipEntityStatusRequest, vec![]);
        let resp = handler.handle(req).unwrap();

        assert_eq!(
            resp.payload_type(),
            UdpPayloadType::DoipEntityStatusResponse as u16
        );
        assert_eq!(resp.payload().len(), ENTITY_STATUS_RESPONSE_LEN);
        assert_eq!(resp.payload()[0], DOIP_NODE_TYPE);
        assert_eq!(resp.payload()[1], 10);
        assert_eq!(resp.payload()[2], 0x00);
        assert_eq!(
            u32::from_be_bytes([
                resp.payload()[3],
                resp.payload()[4],
                resp.payload()[5],
                resp.payload()[6]
            ]),
            65_535
        );
    }

    #[test]
    fn handle_rejects_non_empty_payload() {
        let handler = EntityStatusHandler::new(10, 65_535);
        let req = UdpRequest::new(UdpPayloadType::DoipEntityStatusRequest, vec![0x01]);
        assert!(handler.handle(req).is_err());
    }
}
