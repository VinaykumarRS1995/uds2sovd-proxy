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

use super::{DoipParseable, DoipSerializable, parse_fixed_slice};

/// Alive Check Request (payload type `0x0007`) – sent by the `DoIP` entity to verify
/// a tester is still connected.
///
/// This message carries no payload (zero-length body per ISO 13400-2:2019 §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request;

impl DoipParseable for Request {
    fn parse(_payload: &[u8]) -> crate::Result<Self> {
        Ok(Self)
    }
}

impl DoipSerializable for Request {
    fn serialized_len(&self) -> Option<usize> {
        Some(0)
    }

    /// Alive Check Request carries no payload bytes per ISO 13400-2;
    /// nothing is written to the buffer by design.
    fn write_to(&self, _buf: &mut BytesMut) {
        // Intentionally empty: Alive Check Request has a zero-length payload.
    }
}

/// Alive Check Response (payload type `0x0008`) – sent by the tester in reply,
/// carrying its logical address.
///
/// # Wire Format
/// Payload: `source_address` (2 bytes, big-endian)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    source_address: u16,
}

impl DoipParseable for Response {
    fn parse(payload: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 2] = parse_fixed_slice(payload, "AliveCheck Response")?;
        let source_address = u16::from_be_bytes(bytes);
        Ok(Self { source_address })
    }
}

impl DoipSerializable for Response {
    fn serialized_len(&self) -> Option<usize> {
        Some(Self::LEN)
    }

    fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
    }
}

impl Response {
    /// Fixed wire-format length of the Alive Check Response payload (2-byte source address).
    pub const LEN: usize = 2;

    /// Create a new Alive Check Response with the given tester source address.
    #[must_use]
    pub fn new(source_address: u16) -> Self {
        Self { source_address }
    }

    /// The logical source address of the tester
    #[must_use]
    pub fn source_address(&self) -> u16 {
        self.source_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{DoipParseable, DoipSerializable};

    #[test]
    fn parse_request() {
        let req = Request::parse(&[]).unwrap();
        assert_eq!(req, Request);
    }

    #[test]
    fn request_empty_payload() {
        let req = Request;
        let bytes = req.to_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parse_response() {
        let payload = [0x0E, 0x80];
        let resp = Response::parse(&payload).unwrap();
        assert_eq!(resp.source_address, 0x0E80);
    }

    #[test]
    fn reject_short_response() {
        let short = [0x0E];
        assert!(Response::parse(&short).is_err());
    }

    #[test]
    fn build_response() {
        let resp = Response::new(0x0E80);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 2);
        assert_eq!(&bytes[..], &[0x0E, 0x80]);
    }

    #[test]
    fn roundtrip_response() {
        let original = Response::new(0x0F00);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
