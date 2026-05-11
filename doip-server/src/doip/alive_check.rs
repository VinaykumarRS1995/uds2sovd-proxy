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
//! Alive Check handlers (ISO 13400-2)

use bytes::{BufMut, BytesMut};
use tracing::warn;

use super::{DoipParseable, DoipSerializable, parse_fixed_slice};
use crate::Result;

/// Alive Check Request (payload type `0x0007`) – sent by the `DoIP` entity to verify
/// a tester is still connected.
///
/// This message carries no payload (zero-length body per ISO 13400-2:2019 §7.6).
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliveCheckRequest;

impl DoipParseable for AliveCheckRequest {
    fn parse(_payload: &[u8]) -> Result<Self> {
        Ok(Self)
    }
}

impl DoipSerializable for AliveCheckRequest {
    fn serialized_len(&self) -> Option<usize> {
        Some(0)
    }

    /// Alive Check Request carries no payload bytes per ISO 13400-2;
    /// nothing is written to the buffer by design.
    fn write_to(&self, _buf: &mut BytesMut) {
        // Intentionally empty: Alive Check Request has a zero-length payload.
        warn!(
            "AliveCheckRequest::write_to called — this message has no payload; nothing is written"
        );
    }
}

/// Alive Check Response (payload type `0x0008`) – sent by the tester in reply,
/// carrying its logical address.
///
/// # Wire Format
/// Payload: `source_address` (2 bytes, big-endian)
///
/// `Clone` is derived because [`DoipPayload`](super::payload::DoipPayload) wraps this type and itself derives `Clone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliveCheckResponse {
    source_address: u16,
}

impl DoipParseable for AliveCheckResponse {
    fn parse(payload: &[u8]) -> Result<Self> {
        let bytes: [u8; 2] = parse_fixed_slice(payload, "AliveCheck Response")?;
        let source_address = u16::from_be_bytes(bytes);
        Ok(Self { source_address })
    }
}

impl DoipSerializable for AliveCheckResponse {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
    }
}

impl AliveCheckResponse {
    /// Fixed wire-format length of the Alive Check Response payload (2-byte source address).
    const LEN: usize = 2;

    /// Create a new Alive Check Response with the given tester source address.
    #[must_use]
    pub fn new(source_address: u16) -> Self {
        Self { source_address }
    }

    /// The logical address of the tester that sent this response.
    #[must_use]
    pub fn tester_address(&self) -> u16 {
        self.source_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn parse_request() {
        let req = AliveCheckRequest::parse(&[]).unwrap();
        assert_eq!(req, AliveCheckRequest);
    }

    #[test]
    fn request_empty_payload() {
        let req = AliveCheckRequest;
        let bytes = req.to_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parse_response() {
        let payload = [0x0E, 0x80];
        let resp = AliveCheckResponse::parse(&payload).unwrap();
        assert_eq!(resp.tester_address(), 0x0E80);
    }

    #[test]
    fn reject_short_response() {
        let short = [0x0E];
        assert!(AliveCheckResponse::parse(&short).is_err());
    }

    #[test]
    fn build_response() {
        let resp = AliveCheckResponse::new(0x0E80);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 2);
        assert_eq!(&bytes[..], &[0x0E, 0x80]);
    }

    #[test]
    fn roundtrip_response() {
        let original = AliveCheckResponse::new(0x0F00);
        let bytes = original.to_bytes();
        let parsed = AliveCheckResponse::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
