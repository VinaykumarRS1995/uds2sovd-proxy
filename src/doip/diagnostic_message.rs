// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! Diagnostic Message handlers (ISO 13400-2)

use bytes::{Buf, BufMut, Bytes, BytesMut};

// Diagnostic message positive ack codes per ISO 13400-2 Table 27
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckCode {
    Acknowledged = 0x00,
}

// Diagnostic message negative ack codes per ISO 13400-2 Table 28
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NackCode {
    InvalidSourceAddress = 0x02,
    UnknownTargetAddress = 0x03,
    DiagnosticMessageTooLarge = 0x04,
    OutOfMemory = 0x05,
    TargetUnreachable = 0x06,
    UnknownNetwork = 0x07,
    TransportProtocolError = 0x08,
}

impl NackCode {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x02 => Some(Self::InvalidSourceAddress),
            0x03 => Some(Self::UnknownTargetAddress),
            0x04 => Some(Self::DiagnosticMessageTooLarge),
            0x05 => Some(Self::OutOfMemory),
            0x06 => Some(Self::TargetUnreachable),
            0x07 => Some(Self::UnknownNetwork),
            0x08 => Some(Self::TransportProtocolError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    PayloadTooShort { expected: usize, actual: usize },
    EmptyUserData,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort { expected, actual } => {
                write!(f, "payload too short: need {expected} bytes, got {actual}")
            }
            Self::EmptyUserData => write!(f, "diagnostic message has no user data"),
        }
    }
}

impl std::error::Error for Error {}

// Diagnostic Message - carries UDS data between tester and ECU
// Payload: SA(2) + TA(2) + user_data(1+)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub source_address: u16,
    pub target_address: u16,
    pub user_data: Bytes,
}

impl Message {
    pub const MIN_LEN: usize = 5; // SA + TA + at least 1 byte UDS

    #[must_use]
    pub fn new(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            user_data: data,
        }
    }

    /// Parse a Diagnostic Message from payload bytes
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if payload is less than 5 bytes
    /// Returns `Error::EmptyUserData` if no UDS data is present
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let header: [u8; 4] =
            payload
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::PayloadTooShort {
                    expected: Self::MIN_LEN,
                    actual: payload.len(),
                })?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);

        let user_data =
            payload
                .get(4..)
                .map(Bytes::copy_from_slice)
                .ok_or(Error::PayloadTooShort {
                    expected: Self::MIN_LEN,
                    actual: payload.len(),
                })?;

        if user_data.is_empty() {
            return Err(Error::EmptyUserData);
        }

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }

    /// Parse a Diagnostic Message from a mutable Bytes buffer
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if buffer is less than 5 bytes
    /// Returns `Error::EmptyUserData` if no UDS data is present
    pub fn parse_buf(buf: &mut Bytes) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: buf.len(),
            });
        }

        let source_address = buf.get_u16();
        let target_address = buf.get_u16();
        let user_data = buf.split_off(0);

        if user_data.is_empty() {
            return Err(Error::EmptyUserData);
        }

        Ok(Self {
            source_address,
            target_address,
            user_data,
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4_usize.saturating_add(self.user_data.len()));
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.extend_from_slice(&self.user_data);
    }

    // UDS service ID is first byte of user_data
    pub fn service_id(&self) -> Option<u8> {
        self.user_data.first().copied()
    }
}

// Diagnostic Message Positive Ack (0x8002)
// Payload: SA(2) + TA(2) + ack_code(1) + optional previous_diag_data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositiveAck {
    pub source_address: u16,
    pub target_address: u16,
    pub ack_code: AckCode,
    pub previous_data: Option<Bytes>,
}

impl PositiveAck {
    pub const MIN_LEN: usize = 5;

    #[must_use]
    pub fn new(source: u16, target: u16) -> Self {
        Self {
            source_address: source,
            target_address: target,
            ack_code: AckCode::Acknowledged,
            previous_data: None,
        }
    }

    #[must_use]
    pub fn with_previous_data(source: u16, target: u16, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            ack_code: AckCode::Acknowledged,
            previous_data: Some(data),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let extra = self.previous_data.as_ref().map_or(0, Bytes::len);
        let mut buf = BytesMut::with_capacity(Self::MIN_LEN.saturating_add(extra));
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.put_u8(self.ack_code as u8);
        if let Some(ref data) = self.previous_data {
            buf.extend_from_slice(data);
        }
    }

    /// Parse a Positive Ack from payload bytes
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if payload is less than 5 bytes
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let header: [u8; 4] =
            payload
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::PayloadTooShort {
                    expected: Self::MIN_LEN,
                    actual: payload.len(),
                })?;

        // Verify we have at least MIN_LEN bytes
        if payload.len() < Self::MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: payload.len(),
            });
        }

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);
        let ack_code = AckCode::Acknowledged; // only one value

        let previous_data = payload
            .get(5..)
            .filter(|d| !d.is_empty())
            .map(Bytes::copy_from_slice);

        Ok(Self {
            source_address,
            target_address,
            ack_code,
            previous_data,
        })
    }
}

// Diagnostic Message Negative Ack (0x8003)
// Payload: SA(2) + TA(2) + nack_code(1) + optional previous_diag_data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeAck {
    pub source_address: u16,
    pub target_address: u16,
    pub nack_code: NackCode,
    pub previous_data: Option<Bytes>,
}

impl NegativeAck {
    pub const MIN_LEN: usize = 5;

    #[must_use]
    pub fn new(source: u16, target: u16, code: NackCode) -> Self {
        Self {
            source_address: source,
            target_address: target,
            nack_code: code,
            previous_data: None,
        }
    }

    pub fn with_previous_data(source: u16, target: u16, code: NackCode, data: Bytes) -> Self {
        Self {
            source_address: source,
            target_address: target,
            nack_code: code,
            previous_data: Some(data),
        }
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let extra = self.previous_data.as_ref().map_or(0, Bytes::len);
        let mut buf = BytesMut::with_capacity(Self::MIN_LEN.saturating_add(extra));
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
        buf.put_u16(self.target_address);
        buf.put_u8(self.nack_code as u8);
        if let Some(ref data) = self.previous_data {
            buf.extend_from_slice(data);
        }
    }

    /// Parse a Negative Ack from payload bytes
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if payload is less than 5 bytes
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let header: [u8; 5] = payload
            .get(..Self::MIN_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: payload.len(),
            })?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let target_address = u16::from_be_bytes([header[2], header[3]]);
        let nack_code = NackCode::from_u8(header[4]).unwrap_or(NackCode::TransportProtocolError);

        let previous_data = payload
            .get(5..)
            .filter(|d| !d.is_empty())
            .map(Bytes::copy_from_slice);

        Ok(Self {
            source_address,
            target_address,
            nack_code,
            previous_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nack_code_values() {
        assert_eq!(NackCode::InvalidSourceAddress as u8, 0x02);
        assert_eq!(NackCode::UnknownTargetAddress as u8, 0x03);
        assert_eq!(NackCode::TargetUnreachable as u8, 0x06);
    }

    #[test]
    fn parse_diagnostic_message() {
        // SA=0x0E80, TA=0x1000, UDS=0x22 0xF1 0x90 (ReadDataByID)
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x22, 0xF1, 0x90];
        let msg = Message::parse(&payload).unwrap();

        assert_eq!(msg.source_address, 0x0E80);
        assert_eq!(msg.target_address, 0x1000);
        assert_eq!(msg.user_data.as_ref(), &[0x22, 0xF1, 0x90]);
        assert_eq!(msg.service_id(), Some(0x22));
    }

    #[test]
    fn parse_tester_present() {
        // TesterPresent service
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x3E, 0x00];
        let msg = Message::parse(&payload).unwrap();

        assert_eq!(msg.service_id(), Some(0x3E));
        assert_eq!(msg.user_data.len(), 2);
    }

    #[test]
    fn reject_short_message() {
        let short = [0x0E, 0x80, 0x10, 0x00]; // no user data
        assert!(Message::parse(&short).is_err());
    }

    #[test]
    fn build_diagnostic_message() {
        let uds = Bytes::from_static(&[0x22, 0xF1, 0x90]);
        let msg = Message::new(0x0E80, 0x1000, uds);
        let bytes = msg.to_bytes();

        assert_eq!(&bytes[0..2], &[0x0E, 0x80]);
        assert_eq!(&bytes[2..4], &[0x10, 0x00]);
        assert_eq!(&bytes[4..], &[0x22, 0xF1, 0x90]);
    }

    #[test]
    fn build_positive_ack() {
        let ack = PositiveAck::new(0x1000, 0x0E80);
        let bytes = ack.to_bytes();

        assert_eq!(bytes.len(), 5);
        assert_eq!(&bytes[0..2], &[0x10, 0x00]); // source (ECU)
        assert_eq!(&bytes[2..4], &[0x0E, 0x80]); // target (tester)
        assert_eq!(bytes[4], 0x00); // ack code
    }

    #[test]
    fn build_positive_ack_with_prev_data() {
        let prev = Bytes::from_static(&[0x22, 0xF1, 0x90]);
        let ack = PositiveAck::with_previous_data(0x1000, 0x0E80, prev);
        let bytes = ack.to_bytes();

        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[5..], &[0x22, 0xF1, 0x90]);
    }

    #[test]
    fn build_negative_ack() {
        let nack = NegativeAck::new(0x1000, 0x0E80, NackCode::UnknownTargetAddress);
        let bytes = nack.to_bytes();

        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[4], 0x03);
    }

    #[test]
    fn build_negative_ack_target_unreachable() {
        let nack = NegativeAck::new(0x1000, 0x0E80, NackCode::TargetUnreachable);
        let bytes = nack.to_bytes();
        assert_eq!(bytes[4], 0x06);
    }

    #[test]
    fn parse_positive_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x00];
        let ack = PositiveAck::parse(&payload).unwrap();

        assert_eq!(ack.source_address, 0x1000);
        assert_eq!(ack.target_address, 0x0E80);
        assert!(ack.previous_data.is_none());
    }

    #[test]
    fn parse_negative_ack() {
        let payload = [0x10, 0x00, 0x0E, 0x80, 0x03];
        let nack = NegativeAck::parse(&payload).unwrap();

        assert_eq!(nack.nack_code, NackCode::UnknownTargetAddress);
    }

    #[test]
    fn roundtrip_message() {
        let original = Message::new(0x0E80, 0x1000, Bytes::from_static(&[0x10, 0x01]));
        let bytes = original.to_bytes();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_positive_ack() {
        let original = PositiveAck::new(0x1000, 0x0E80);
        let bytes = original.to_bytes();
        let parsed = PositiveAck::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_negative_ack() {
        let original = NegativeAck::new(0x1000, 0x0E80, NackCode::OutOfMemory);
        let bytes = original.to_bytes();
        let parsed = NegativeAck::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
