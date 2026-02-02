//! Alive Check handlers (ISO 13400-2)

use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    PayloadTooShort { expected: usize, actual: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort { expected, actual } => {
                write!(f, "payload too short: need {} bytes, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for Error {}

// Alive Check Request (0x0007) - no payload
// Server sends this to check if tester is still connected
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request;

impl Request {
    pub fn parse(_payload: &[u8]) -> Result<Self, Error> {
        Ok(Self)
    }

    pub fn to_bytes(&self) -> Bytes {
        Bytes::new()
    }
}

// Alive Check Response (0x0008) - 2 byte source address
// Tester responds with its logical address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub source_address: u16,
}

impl Response {
    pub const LEN: usize = 2;

    pub fn new(source_address: u16) -> Self {
        Self { source_address }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < Self::LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::LEN,
                actual: payload.len(),
            });
        }

        let source_address = u16::from_be_bytes([payload[0], payload[1]]);
        Ok(Self { source_address })
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(Self::LEN);
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u16(self.source_address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
