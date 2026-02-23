// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! Routing Activation handlers (ISO 13400-2)

use bytes::{Buf, BufMut, Bytes, BytesMut};

// Response codes per ISO 13400-2 Table 25
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    UnknownSourceAddress = 0x00,
    AllSocketsRegistered = 0x01,
    DifferentSourceAddress = 0x02,
    SourceAddressAlreadyActive = 0x03,
    MissingAuthentication = 0x04,
    RejectedConfirmation = 0x05,
    UnsupportedActivationType = 0x06,
    TlsRequired = 0x07,
    SuccessfullyActivated = 0x10,
    ConfirmationRequired = 0x11,
}

impl ResponseCode {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::UnknownSourceAddress),
            0x01 => Some(Self::AllSocketsRegistered),
            0x02 => Some(Self::DifferentSourceAddress),
            0x03 => Some(Self::SourceAddressAlreadyActive),
            0x04 => Some(Self::MissingAuthentication),
            0x05 => Some(Self::RejectedConfirmation),
            0x06 => Some(Self::UnsupportedActivationType),
            0x07 => Some(Self::TlsRequired),
            0x10 => Some(Self::SuccessfullyActivated),
            0x11 => Some(Self::ConfirmationRequired),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(
            self,
            Self::SuccessfullyActivated | Self::ConfirmationRequired
        )
    }
}

// Activation types per ISO 13400-2 Table 24
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActivationType {
    Default = 0x00,
    WwhObd = 0x01,
    CentralSecurity = 0xE0,
}

impl ActivationType {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::WwhObd),
            0xE0 => Some(Self::CentralSecurity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    PayloadTooShort { expected: usize, actual: usize },
    UnknownResponseCode(u8),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort { expected, actual } => {
                write!(f, "payload too short: need {expected} bytes, got {actual}")
            }
            Self::UnknownResponseCode(code) => write!(f, "unknown response code: 0x{code:02X}"),
        }
    }
}

impl std::error::Error for Error {}

// Routing Activation Request - payload is 7 bytes min, 11 with OEM data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub source_address: u16,
    pub activation_type: u8,
    pub reserved: u32,
    pub oem_specific: Option<u32>,
}

impl Request {
    pub const MIN_LEN: usize = 7;
    pub const MAX_LEN: usize = 11;

    /// Parse a Routing Activation Request from payload bytes
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if payload is less than 7 bytes
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let header: [u8; 7] = payload
            .get(..Self::MIN_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: payload.len(),
            })?;

        let source_address = u16::from_be_bytes([header[0], header[1]]);
        let activation_type = header[2];
        let reserved = u32::from_be_bytes([header[3], header[4], header[5], header[6]]);

        let oem_specific = payload
            .get(7..Self::MAX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes);

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            oem_specific,
        })
    }

    /// Parse routing activation request from buffer
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or contains invalid data.
    pub fn parse_buf(buf: &mut Bytes) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: buf.len(),
            });
        }

        let source_address = buf.get_u16();
        let activation_type = buf.get_u8();
        let reserved = buf.get_u32();
        let oem_specific = if buf.remaining() >= 4 {
            Some(buf.get_u32())
        } else {
            None
        };

        Ok(Self {
            source_address,
            activation_type,
            reserved,
            oem_specific,
        })
    }

    #[must_use]
    pub fn activation_type_enum(&self) -> Option<ActivationType> {
        ActivationType::from_u8(self.activation_type)
    }

    #[must_use]
    pub fn validate(&self) -> Option<ResponseCode> {
        if ActivationType::from_u8(self.activation_type).is_none() {
            return Some(ResponseCode::UnsupportedActivationType);
        }
        None
    }
}

// Routing Activation Response - 9 bytes min, 13 with OEM data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub tester_address: u16,
    pub entity_address: u16,
    pub response_code: ResponseCode,
    pub reserved: u32,
    pub oem_specific: Option<u32>,
}

impl Response {
    pub const MIN_LEN: usize = 9;
    pub const MAX_LEN: usize = 13;

    #[must_use]
    pub fn success(tester_address: u16, entity_address: u16) -> Self {
        Self {
            tester_address,
            entity_address,
            response_code: ResponseCode::SuccessfullyActivated,
            reserved: 0,
            oem_specific: None,
        }
    }

    #[must_use]
    pub fn denial(tester_address: u16, entity_address: u16, code: ResponseCode) -> Self {
        Self {
            tester_address,
            entity_address,
            response_code: code,
            reserved: 0,
            oem_specific: None,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let len = if self.oem_specific.is_some() {
            Self::MAX_LEN
        } else {
            Self::MIN_LEN
        };
        let mut buf = BytesMut::with_capacity(len);
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.tester_address);
        buf.put_u16(self.entity_address);
        buf.put_u8(self.response_code as u8);
        buf.put_u32(self.reserved);
        if let Some(oem) = self.oem_specific {
            buf.put_u32(oem);
        }
    }

    /// Parse a Routing Activation Response from payload bytes
    ///
    /// # Errors
    /// Returns `Error::PayloadTooShort` if payload is less than 9 bytes
    /// Returns `Error::UnknownResponseCode` if response code is invalid
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let header: [u8; 9] = payload
            .get(..Self::MIN_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: payload.len(),
            })?;

        let tester_address = u16::from_be_bytes([header[0], header[1]]);
        let entity_address = u16::from_be_bytes([header[2], header[3]]);
        let response_code =
            ResponseCode::from_u8(header[4]).ok_or(Error::UnknownResponseCode(header[4]))?;
        let reserved = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);

        let oem_specific = payload
            .get(9..Self::MAX_LEN)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes);

        Ok(Self {
            tester_address,
            entity_address,
            response_code,
            reserved,
            oem_specific,
        })
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.response_code.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_code_success_check() {
        assert!(ResponseCode::SuccessfullyActivated.is_success());
        assert!(ResponseCode::ConfirmationRequired.is_success());
        assert!(!ResponseCode::UnknownSourceAddress.is_success());
        assert!(!ResponseCode::TlsRequired.is_success());
    }

    #[test]
    fn response_code_values() {
        assert_eq!(ResponseCode::UnknownSourceAddress as u8, 0x00);
        assert_eq!(ResponseCode::SuccessfullyActivated as u8, 0x10);
        assert_eq!(ResponseCode::ConfirmationRequired as u8, 0x11);
    }

    #[test]
    fn parse_minimal_request() {
        let payload = [0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
        let req = Request::parse(&payload).unwrap();

        assert_eq!(req.source_address, 0x0E80);
        assert_eq!(req.activation_type, 0x00);
        assert_eq!(req.reserved, 0);
        assert!(req.oem_specific.is_none());
    }

    #[test]
    fn parse_request_with_oem() {
        let payload = [
            0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let req = Request::parse(&payload).unwrap();
        assert_eq!(req.oem_specific, Some(0xDEAD_BEEF));
    }

    #[test]
    fn parse_wwh_obd_request() {
        let payload = [0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let req = Request::parse(&payload).unwrap();
        assert_eq!(req.activation_type_enum(), Some(ActivationType::WwhObd));
    }

    #[test]
    fn reject_short_request() {
        let short = [0x0E, 0x80, 0x00, 0x00];
        assert!(Request::parse(&short).is_err());
    }

    #[test]
    fn validate_bad_activation_type() {
        let payload = [0x0E, 0x80, 0x99, 0x00, 0x00, 0x00, 0x00];
        let req = Request::parse(&payload).unwrap();
        assert_eq!(
            req.validate(),
            Some(ResponseCode::UnsupportedActivationType)
        );
    }

    #[test]
    fn build_success_response() {
        let resp = Response::success(0x0E80, 0x1000);
        assert_eq!(resp.tester_address, 0x0E80);
        assert_eq!(resp.entity_address, 0x1000);
        assert!(resp.is_success());
    }

    #[test]
    fn build_denial_response() {
        let resp = Response::denial(0x0E80, 0x1000, ResponseCode::AllSocketsRegistered);
        assert!(!resp.is_success());
    }

    #[test]
    fn serialize_response() {
        let resp = Response::success(0x0E80, 0x1000);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[0..2], &[0x0E, 0x80]);
        assert_eq!(&bytes[2..4], &[0x10, 0x00]);
        assert_eq!(bytes[4], 0x10);
    }

    #[test]
    fn serialize_response_with_oem() {
        let mut resp = Response::success(0x0E80, 0x1000);
        resp.oem_specific = Some(0x1234_5678);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 13);
        assert_eq!(&bytes[9..13], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn parse_success_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
        let resp = Response::parse(&payload).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.tester_address, 0x0E80);
        assert_eq!(resp.entity_address, 0x1000);
    }

    #[test]
    fn parse_denial_response() {
        let payload = [0x0E, 0x80, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let resp = Response::parse(&payload).unwrap();
        assert!(!resp.is_success());
        assert_eq!(resp.response_code, ResponseCode::AllSocketsRegistered);
    }

    #[test]
    fn roundtrip_response() {
        let original = Response::success(0x0E80, 0x1000);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_response_with_oem() {
        let mut original = Response::denial(0x0F00, 0x2000, ResponseCode::MissingAuthentication);
        original.oem_specific = Some(0xCAFE_BABE);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
