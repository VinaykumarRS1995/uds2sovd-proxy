//! Vehicle Identification handlers (ISO 13400-2)

use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    PayloadTooShort { expected: usize, actual: usize },
    InvalidVinLength(usize),
    InvalidEidLength(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort { expected, actual } => {
                write!(f, "payload too short: need {} bytes, got {}", expected, actual)
            }
            Self::InvalidVinLength(len) => write!(f, "VIN must be 17 bytes, got {}", len),
            Self::InvalidEidLength(len) => write!(f, "EID must be 6 bytes, got {}", len),
        }
    }
}

impl std::error::Error for Error {}

// Vehicle Identification Request (0x0001) - no payload
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request;

impl Request {
    pub fn parse(_payload: &[u8]) -> Result<Self, Error> {
        Ok(Self)
    }
}

// Vehicle Identification Request with EID (0x0002) - 6 byte EID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestWithEid {
    pub eid: [u8; 6],
}

impl RequestWithEid {
    pub const LEN: usize = 6;

    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < Self::LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::LEN,
                actual: payload.len(),
            });
        }

        let mut eid = [0u8; 6];
        eid.copy_from_slice(&payload[0..6]);
        Ok(Self { eid })
    }

    pub fn new(eid: [u8; 6]) -> Self {
        Self { eid }
    }
}

// Vehicle Identification Request with VIN (0x0003) - 17 byte VIN
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestWithVin {
    pub vin: [u8; 17],
}

impl RequestWithVin {
    pub const LEN: usize = 17;

    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < Self::LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::LEN,
                actual: payload.len(),
            });
        }

        let mut vin = [0u8; 17];
        vin.copy_from_slice(&payload[0..17]);
        Ok(Self { vin })
    }

    pub fn new(vin: [u8; 17]) -> Self {
        Self { vin }
    }

    pub fn vin_string(&self) -> String {
        String::from_utf8_lossy(&self.vin).to_string()
    }
}

// Further action codes for vehicle identification response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FurtherAction {
    NoFurtherAction = 0x00,
    RoutingActivationRequired = 0x10,
}

// Sync status for vehicle identification response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncStatus {
    Synchronized = 0x00,
    NotSynchronized = 0x10,
}

// Vehicle Identification Response (0x0004)
// VIN(17) + LogicalAddr(2) + EID(6) + GID(6) + FurtherAction(1) = 32 bytes min
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub vin: [u8; 17],
    pub logical_address: u16,
    pub eid: [u8; 6],
    pub gid: [u8; 6],
    pub further_action: FurtherAction,
    pub sync_status: Option<SyncStatus>,
}

impl Response {
    pub const MIN_LEN: usize = 32; // without sync status
    pub const MAX_LEN: usize = 33; // with sync status

    pub fn new(vin: [u8; 17], logical_address: u16, eid: [u8; 6], gid: [u8; 6]) -> Self {
        Self {
            vin,
            logical_address,
            eid,
            gid,
            further_action: FurtherAction::NoFurtherAction,
            sync_status: None,
        }
    }

    pub fn with_routing_required(mut self) -> Self {
        self.further_action = FurtherAction::RoutingActivationRequired;
        self
    }

    pub fn with_sync_status(mut self, status: SyncStatus) -> Self {
        self.sync_status = Some(status);
        self
    }

    pub fn to_bytes(&self) -> Bytes {
        let len = if self.sync_status.is_some() { Self::MAX_LEN } else { Self::MIN_LEN };
        let mut buf = BytesMut::with_capacity(len);
        self.write_to(&mut buf);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.vin);
        buf.put_u16(self.logical_address);
        buf.extend_from_slice(&self.eid);
        buf.extend_from_slice(&self.gid);
        buf.put_u8(self.further_action as u8);
        if let Some(status) = self.sync_status {
            buf.put_u8(status as u8);
        }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < Self::MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: Self::MIN_LEN,
                actual: payload.len(),
            });
        }

        let mut vin = [0u8; 17];
        vin.copy_from_slice(&payload[0..17]);

        let logical_address = u16::from_be_bytes([payload[17], payload[18]]);

        let mut eid = [0u8; 6];
        eid.copy_from_slice(&payload[19..25]);

        let mut gid = [0u8; 6];
        gid.copy_from_slice(&payload[25..31]);

        let further_action = match payload[31] {
            0x10 => FurtherAction::RoutingActivationRequired,
            _ => FurtherAction::NoFurtherAction,
        };

        let sync_status = if payload.len() >= Self::MAX_LEN {
            Some(match payload[32] {
                0x10 => SyncStatus::NotSynchronized,
                _ => SyncStatus::Synchronized,
            })
        } else {
            None
        };

        Ok(Self {
            vin,
            logical_address,
            eid,
            gid,
            further_action,
            sync_status,
        })
    }

    pub fn vin_string(&self) -> String {
        String::from_utf8_lossy(&self.vin).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_request() {
        let req = Request::parse(&[]).unwrap();
        assert_eq!(req, Request);
    }

    #[test]
    fn parse_request_with_eid() {
        let payload = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let req = RequestWithEid::parse(&payload).unwrap();
        assert_eq!(req.eid, [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    }

    #[test]
    fn reject_short_eid_request() {
        let short = [0x00, 0x1A, 0x2B];
        assert!(RequestWithEid::parse(&short).is_err());
    }

    #[test]
    fn parse_request_with_vin() {
        let vin = b"WVWZZZ3CZWE123456";
        let req = RequestWithVin::parse(vin).unwrap();
        assert_eq!(req.vin_string(), "WVWZZZ3CZWE123456");
    }

    #[test]
    fn reject_short_vin_request() {
        let short = b"WVWZZZ";
        assert!(RequestWithVin::parse(short).is_err());
    }

    #[test]
    fn build_basic_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let resp = Response::new(vin, 0x1000, eid, gid);

        assert_eq!(resp.logical_address, 0x1000);
        assert_eq!(resp.further_action, FurtherAction::NoFurtherAction);
        assert!(resp.sync_status.is_none());
    }

    #[test]
    fn build_response_with_routing_required() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0; 6];
        let gid = [0; 6];

        let resp = Response::new(vin, 0x1000, eid, gid).with_routing_required();
        assert_eq!(resp.further_action, FurtherAction::RoutingActivationRequired);
    }

    #[test]
    fn serialize_response_minimal() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let resp = Response::new(vin, 0x1000, eid, gid);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[0..17], b"WVWZZZ3CZWE123456");
        assert_eq!(&bytes[17..19], &[0x10, 0x00]); // logical address
    }

    #[test]
    fn serialize_response_with_sync() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0; 6];
        let gid = [0; 6];

        let resp = Response::new(vin, 0x1000, eid, gid)
            .with_sync_status(SyncStatus::Synchronized);
        let bytes = resp.to_bytes();

        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[32], 0x00); // sync status
    }

    #[test]
    fn parse_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let original = Response::new(vin, 0x1000, eid, gid);
        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();

        assert_eq!(parsed.vin, vin);
        assert_eq!(parsed.logical_address, 0x1000);
        assert_eq!(parsed.eid, eid);
        assert_eq!(parsed.gid, gid);
    }

    #[test]
    fn roundtrip_response() {
        let vin = *b"WVWZZZ3CZWE123456";
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let gid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

        let original = Response::new(vin, 0x1000, eid, gid)
            .with_routing_required()
            .with_sync_status(SyncStatus::NotSynchronized);

        let bytes = original.to_bytes();
        let parsed = Response::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
