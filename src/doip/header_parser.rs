//! DoIP Header Parser

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericNackCode {
    IncorrectPatternFormat = 0x00,
    UnknownPayloadType = 0x01,
    MessageTooLarge = 0x02,
    OutOfMemory = 0x03,
    InvalidPayloadLength = 0x04,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidHeader(String),
    Io(io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            Self::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
pub const DEFAULT_PROTOCOL_VERSION_INV: u8 = 0xFD;
pub const DOIP_HEADER_LENGTH: usize = 8;
/// Maximum DoIP message size (4MB) - provides DoS protection while allowing
/// large diagnostic data transfers. Can be customized via DoipCodec::with_max_payload_size().
pub const MAX_DOIP_MESSAGE_SIZE: u32 = 0x0040_0000; // 4MB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadType {
    GenericNack = 0x0000,
    VehicleIdentificationRequest = 0x0001,
    VehicleIdentificationRequestWithEid = 0x0002,
    VehicleIdentificationRequestWithVin = 0x0003,
    VehicleIdentificationResponse = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DoipEntityStatusRequest = 0x4001,
    DoipEntityStatusResponse = 0x4002,
    DiagnosticPowerModeRequest = 0x4003,
    DiagnosticPowerModeResponse = 0x4004,
    DiagnosticMessage = 0x8001,
    DiagnosticMessagePositiveAck = 0x8002,
    DiagnosticMessageNegativeAck = 0x8003,
}

impl PayloadType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::GenericNack),
            0x0001 => Some(Self::VehicleIdentificationRequest),
            0x0002 => Some(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Some(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Some(Self::VehicleIdentificationResponse),
            0x0005 => Some(Self::RoutingActivationRequest),
            0x0006 => Some(Self::RoutingActivationResponse),
            0x0007 => Some(Self::AliveCheckRequest),
            0x0008 => Some(Self::AliveCheckResponse),
            0x4001 => Some(Self::DoipEntityStatusRequest),
            0x4002 => Some(Self::DoipEntityStatusResponse),
            0x4003 => Some(Self::DiagnosticPowerModeRequest),
            0x4004 => Some(Self::DiagnosticPowerModeResponse),
            0x8001 => Some(Self::DiagnosticMessage),
            0x8002 => Some(Self::DiagnosticMessagePositiveAck),
            0x8003 => Some(Self::DiagnosticMessageNegativeAck),
            _ => None,
        }
    }

    pub const fn min_payload_length(self) -> usize {
        match self {
            Self::GenericNack => 1,
            Self::VehicleIdentificationRequest => 0,
            Self::VehicleIdentificationRequestWithEid => 6,
            Self::VehicleIdentificationRequestWithVin => 17,
            Self::VehicleIdentificationResponse => 32,
            Self::RoutingActivationRequest => 7,
            Self::RoutingActivationResponse => 9,
            Self::AliveCheckRequest => 0,
            Self::AliveCheckResponse => 2,
            Self::DoipEntityStatusRequest => 0,
            Self::DoipEntityStatusResponse => 3,
            Self::DiagnosticPowerModeRequest => 0,
            Self::DiagnosticPowerModeResponse => 1,
            Self::DiagnosticMessage => 5,
            Self::DiagnosticMessagePositiveAck => 5,
            Self::DiagnosticMessageNegativeAck => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoipHeader {
    pub version: u8,
    pub inverse_version: u8,
    pub payload_type: u16,
    pub payload_length: u32,
}

impl DoipHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOIP_HEADER_LENGTH {
            return Err(ParseError::InvalidHeader(format!(
                "header too short: expected {}, got {}",
                DOIP_HEADER_LENGTH,
                data.len()
            )));
        }
        Ok(Self {
            version: data[0],
            inverse_version: data[1],
            payload_type: u16::from_be_bytes([data[2], data[3]]),
            payload_length: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    pub fn parse_from_buf(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < DOIP_HEADER_LENGTH {
            return Err(ParseError::InvalidHeader(format!(
                "header too short: expected {}, got {}",
                DOIP_HEADER_LENGTH,
                buf.len()
            )));
        }
        Ok(Self {
            version: buf.get_u8(),
            inverse_version: buf.get_u8(),
            payload_type: buf.get_u16(),
            payload_length: buf.get_u32(),
        })
    }

    pub fn validate(&self) -> Option<GenericNackCode> {
        if self.version != DEFAULT_PROTOCOL_VERSION {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }
        if self.inverse_version != DEFAULT_PROTOCOL_VERSION_INV {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }
        if self.version ^ self.inverse_version != 0xFF {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }

        let payload_type = match PayloadType::from_u16(self.payload_type) {
            Some(pt) => pt,
            None => return Some(GenericNackCode::UnknownPayloadType),
        };

        if self.payload_length > MAX_DOIP_MESSAGE_SIZE {
            return Some(GenericNackCode::MessageTooLarge);
        }
        if (self.payload_length as usize) < payload_type.min_payload_length() {
            return Some(GenericNackCode::InvalidPayloadLength);
        }
        None
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_none()
    }

    pub const fn total_length(&self) -> usize {
        DOIP_HEADER_LENGTH + self.payload_length as usize
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DOIP_HEADER_LENGTH);
        buf.put_u8(self.version);
        buf.put_u8(self.inverse_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload_length);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.inverse_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload_length);
    }
}

impl Default for DoipHeader {
    fn default() -> Self {
        Self {
            version: DEFAULT_PROTOCOL_VERSION,
            inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
            payload_type: 0,
            payload_length: 0,
        }
    }
}

impl std::fmt::Display for DoipHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let payload_name = PayloadType::from_u16(self.payload_type)
            .map(|pt| format!("{:?}", pt))
            .unwrap_or_else(|| format!("Unknown(0x{:04X})", self.payload_type));
        write!(
            f,
            "DoipHeader {{ version: 0x{:02X}, type: {}, length: {} }}",
            self.version, payload_name, self.payload_length
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoipMessage {
    pub header: DoipHeader,
    pub payload: Bytes,
}

impl DoipMessage {
    pub fn new(payload_type: PayloadType, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type: payload_type as u16,
                payload_length: payload.len() as u32,
            },
            payload,
        }
    }

    pub fn with_raw_type(payload_type: u16, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type,
                payload_length: payload.len() as u32,
            },
            payload,
        }
    }

    pub fn payload_type(&self) -> Option<PayloadType> {
        PayloadType::from_u16(self.header.payload_type)
    }

    pub fn total_length(&self) -> usize {
        DOIP_HEADER_LENGTH + self.payload.len()
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.total_length());
        self.header.write_to(&mut buf);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Header,
    Payload(DoipHeader),
}

#[derive(Debug)]
pub struct DoipCodec {
    state: DecodeState,
    max_payload_size: u32,
}

impl DoipCodec {
    pub fn new() -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: MAX_DOIP_MESSAGE_SIZE,
        }
    }

    pub fn with_max_payload_size(max_size: u32) -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: max_size,
        }
    }
}

impl Default for DoipCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for DoipCodec {
    type Item = DoipMessage;
    type Error = io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                DecodeState::Header => {
                    if src.len() < DOIP_HEADER_LENGTH {
                        src.reserve(DOIP_HEADER_LENGTH);
                        return Ok(None);
                    }

                    let header = DoipHeader::parse(&src[..DOIP_HEADER_LENGTH])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    if let Some(nack_code) = header.validate() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("validation failed: {:?}", nack_code),
                        ));
                    }

                    if header.payload_length > self.max_payload_size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "payload too large: {} > {}",
                                header.payload_length, self.max_payload_size
                            ),
                        ));
                    }

                    src.reserve(header.total_length());
                    self.state = DecodeState::Payload(header);
                }

                DecodeState::Payload(header) => {
                    if src.len() < header.total_length() {
                        return Ok(None);
                    }

                    let _ = src.split_to(DOIP_HEADER_LENGTH);
                    let payload = src.split_to(header.payload_length as usize).freeze();

                    self.state = DecodeState::Header;
                    return Ok(Some(DoipMessage { header, payload }));
                }
            }
        }
    }
}

impl Encoder<DoipMessage> for DoipCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: DoipMessage,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        dst.reserve(item.total_length());
        item.header.write_to(dst);
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper to build a valid DoIP header quickly ---
    fn make_header(payload_type: u16, payload_len: u32) -> DoipHeader {
        DoipHeader {
            version: 0x02,
            inverse_version: 0xFD,
            payload_type,
            payload_length: payload_len,
        }
    }

    // -------------------------------------------------------------------------
    // Basic header parsing - the bread and butter
    // -------------------------------------------------------------------------

    #[test]
    fn parse_vehicle_id_request_from_tester() {
        // Real-world: tester broadcasts "who's there?" on UDP
        let raw = [0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x0001);
        assert_eq!(hdr.payload_length, 0);
        assert!(hdr.is_valid());
    }

    #[test]
    fn parse_diagnostic_message_with_uds_payload() {
        // Tester sends UDS request: SA=0x0E80, TA=0x1001, SID=0x22 (ReadDataByID)
        let raw = [0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x07];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x8001); // DiagnosticMessage
        assert_eq!(hdr.payload_length, 7);    // 2+2+3 = SA+TA+UDS
    }

    #[test]
    fn parse_routing_activation_request() {
        // Tester wants to start a diagnostic session
        let raw = [0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07];
        let hdr = DoipHeader::parse(&raw).unwrap();

        assert_eq!(hdr.payload_type, 0x0005);
        assert!(hdr.is_valid());
    }

    #[test]
    fn reject_truncated_header() {
        // Only 4 bytes arrived - not enough
        let partial = [0x02, 0xFD, 0x00, 0x01];
        assert!(DoipHeader::parse(&partial).is_err());
    }

    #[test]
    fn extra_bytes_after_header_are_ignored() {
        // Header + some payload bytes mixed in
        let raw = [0x02, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD];
        let hdr = DoipHeader::parse(&raw).unwrap();
        assert_eq!(hdr.payload_length, 0); // Parses only header
    }

    // -------------------------------------------------------------------------
    // Validation - reject bad packets before processing
    // -------------------------------------------------------------------------

    #[test]
    fn reject_wrong_protocol_version() {
        // Someone sends version 0x03 - we only support 0x02
        let hdr = DoipHeader {
            version: 0x03,
            inverse_version: 0xFC,
            payload_type: 0x0001,
            payload_length: 0,
        };
        assert_eq!(hdr.validate(), Some(GenericNackCode::IncorrectPatternFormat));
    }

    #[test]
    fn reject_corrupted_inverse_version() {
        // Inverse should be 0xFD for version 0x02, but we got 0xFC
        let hdr = DoipHeader {
            version: 0x02,
            inverse_version: 0xFC, // Wrong!
            payload_type: 0x0001,
            payload_length: 0,
        };
        assert_eq!(hdr.validate(), Some(GenericNackCode::IncorrectPatternFormat));
    }

    #[test]
    fn reject_unknown_payload_type() {
        // 0x1234 is not a valid DoIP payload type
        let hdr = make_header(0x1234, 0);
        assert_eq!(hdr.validate(), Some(GenericNackCode::UnknownPayloadType));
    }

    #[test]
    fn reject_oversized_message() {
        // Payload claims to be 256MB - way too big
        let hdr = make_header(0x8001, MAX_DOIP_MESSAGE_SIZE + 1);
        assert_eq!(hdr.validate(), Some(GenericNackCode::MessageTooLarge));
    }

    #[test]
    fn reject_diagnostic_msg_with_too_small_payload() {
        // DiagnosticMessage needs at least 5 bytes (SA + TA + 1 UDS byte)
        let hdr = make_header(0x8001, 3);
        assert_eq!(hdr.validate(), Some(GenericNackCode::InvalidPayloadLength));
    }

    #[test]
    fn accept_max_allowed_payload_size() {
        let hdr = make_header(0x8001, MAX_DOIP_MESSAGE_SIZE);
        assert!(hdr.is_valid());
    }

    // -------------------------------------------------------------------------
    // PayloadType enum - mapping values correctly
    // -------------------------------------------------------------------------

    #[test]
    fn payload_type_lookup_works() {
        assert_eq!(PayloadType::from_u16(0x0001), Some(PayloadType::VehicleIdentificationRequest));
        assert_eq!(PayloadType::from_u16(0x0005), Some(PayloadType::RoutingActivationRequest));
        assert_eq!(PayloadType::from_u16(0x8001), Some(PayloadType::DiagnosticMessage));
        assert_eq!(PayloadType::from_u16(0x8002), Some(PayloadType::DiagnosticMessagePositiveAck));
    }

    #[test]
    fn payload_type_gaps_return_none() {
        // These are in gaps between valid ranges
        assert!(PayloadType::from_u16(0x0009).is_none());
        assert!(PayloadType::from_u16(0x4000).is_none());
        assert!(PayloadType::from_u16(0x8000).is_none());
        assert!(PayloadType::from_u16(0xFFFF).is_none());
    }

    #[test]
    fn minimum_payload_lengths_per_spec() {
        // ISO 13400-2 requirements
        assert_eq!(PayloadType::VehicleIdentificationRequest.min_payload_length(), 0);
        assert_eq!(PayloadType::RoutingActivationRequest.min_payload_length(), 7);
        assert_eq!(PayloadType::DiagnosticMessage.min_payload_length(), 5);
        assert_eq!(PayloadType::AliveCheckResponse.min_payload_length(), 2);
    }

    // -------------------------------------------------------------------------
    // DoipMessage - wrapping header + payload together
    // -------------------------------------------------------------------------

    #[test]
    fn create_tester_present_message() {
        // UDS TesterPresent: 0x3E 0x00
        let uds = Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x3E, 0x00]);
        let msg = DoipMessage::new(PayloadType::DiagnosticMessage, uds);

        assert_eq!(msg.header.payload_type, 0x8001);
        assert_eq!(msg.header.payload_length, 6);
        assert_eq!(msg.payload_type(), Some(PayloadType::DiagnosticMessage));
    }

    #[test]
    fn create_vehicle_id_broadcast() {
        // Empty payload for discovery
        let msg = DoipMessage::new(PayloadType::VehicleIdentificationRequest, Bytes::new());

        assert_eq!(msg.header.payload_length, 0);
        assert_eq!(msg.total_length(), 8); // Just the header
    }

    #[test]
    fn message_with_unknown_type() {
        // For testing/fuzzing - create msg with invalid type
        let msg = DoipMessage::with_raw_type(0xBEEF, Bytes::new());
        assert_eq!(msg.payload_type(), None);
    }

    #[test]
    fn serialize_message_to_wire_format() {
        let msg = DoipMessage::new(
            PayloadType::AliveCheckRequest,
            Bytes::new()
        );
        let wire = msg.to_bytes();

        assert_eq!(wire.len(), 8);
        assert_eq!(&wire[..4], &[0x02, 0xFD, 0x00, 0x07]); // Version + type
        assert_eq!(&wire[4..8], &[0x00, 0x00, 0x00, 0x00]); // Length = 0
    }

    // -------------------------------------------------------------------------
    // Codec - TCP stream framing
    // -------------------------------------------------------------------------

    #[test]
    fn decode_complete_alive_check_response() {
        let mut codec = DoipCodec::new();
        // AliveCheckResponse with source address 0x0E80
        let mut buf = BytesMut::from(&[
            0x02, 0xFD, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02,
            0x0E, 0x80
        ][..]);

        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.header.payload_type, 0x0008);
        assert_eq!(msg.payload.as_ref(), &[0x0E, 0x80]);
        assert!(buf.is_empty()); // Consumed everything
    }

    #[test]
    fn wait_for_more_data_when_header_incomplete() {
        let mut codec = DoipCodec::new();
        let mut buf = BytesMut::from(&[0x02, 0xFD, 0x00][..]); // Only 3 bytes

        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3); // Nothing consumed
    }

    #[test]
    fn wait_for_more_data_when_payload_incomplete() {
        let mut codec = DoipCodec::new();
        // Header says 5 bytes payload, but only 2 arrived
        let mut buf = BytesMut::from(&[
            0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x0E, 0x80
        ][..]);

        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_back_to_back_messages() {
        let mut codec = DoipCodec::new();
        let mut buf = BytesMut::from(&[
            // Msg 1: AliveCheckRequest
            0x02, 0xFD, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
            // Msg 2: AliveCheckResponse
            0x02, 0xFD, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x0E, 0x80,
        ][..]);

        let m1 = codec.decode(&mut buf).unwrap().unwrap();
        let m2 = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(m1.header.payload_type, 0x0007);
        assert_eq!(m2.header.payload_type, 0x0008);
        assert!(buf.is_empty());
    }

    #[test]
    fn reject_invalid_header_in_stream() {
        let mut codec = DoipCodec::new();
        // Bad version
        let mut buf = BytesMut::from(&[
            0x01, 0xFE, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ][..]);

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn respect_custom_max_payload_size() {
        let mut codec = DoipCodec::with_max_payload_size(100);
        // Payload length = 101, over our limit
        let mut buf = BytesMut::from(&[
            0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x65
        ][..]);

        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encode_diagnostic_message() {
        let mut codec = DoipCodec::new();
        let payload = Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x3E]);
        let msg = DoipMessage::new(PayloadType::DiagnosticMessage, payload);

        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();

        assert_eq!(&buf[..4], &[0x02, 0xFD, 0x80, 0x01]);
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x00, 0x05]);
        assert_eq!(&buf[8..], &[0x0E, 0x80, 0x10, 0x01, 0x3E]);
    }

    // -------------------------------------------------------------------------
    // Round-trip: encode then decode should give same data
    // -------------------------------------------------------------------------

    #[test]
    fn roundtrip_diagnostic_message() {
        let mut codec = DoipCodec::new();
        let original = DoipMessage::new(
            PayloadType::DiagnosticMessage,
            Bytes::from_static(&[0x0E, 0x80, 0x10, 0x01, 0x22, 0xF1, 0x90])
        );

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(original.header, decoded.header);
        assert_eq!(original.payload, decoded.payload);
    }

    #[test]
    fn roundtrip_header_only() {
        let original = make_header(0x8001, 42);
        let bytes = original.to_bytes();
        let parsed = DoipHeader::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    // -------------------------------------------------------------------------
    // Edge cases and error handling
    // -------------------------------------------------------------------------

    #[test]
    fn handle_all_zeros_gracefully() {
        let garbage = [0x00; 8];
        let hdr = DoipHeader::parse(&garbage).unwrap();
        assert!(!hdr.is_valid()); // Wrong version, but doesn't panic
    }

    #[test]
    fn handle_all_ones_gracefully() {
        let garbage = [0xFF; 8];
        let hdr = DoipHeader::parse(&garbage).unwrap();
        assert!(!hdr.is_valid());
    }

    #[test]
    fn parse_error_shows_useful_message() {
        let err = ParseError::InvalidHeader("buffer too short".into());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid header"));
        assert!(msg.contains("buffer too short"));
    }

    #[test]
    fn io_errors_convert_to_parse_errors() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "connection lost");
        let parse_err: ParseError = io_err.into();
        match parse_err {
            ParseError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            _ => panic!("expected Io variant"),
        }
    }

    #[test]
    fn nack_codes_have_correct_values() {
        // Per ISO 13400-2 Table 17
        assert_eq!(GenericNackCode::IncorrectPatternFormat as u8, 0x00);
        assert_eq!(GenericNackCode::UnknownPayloadType as u8, 0x01);
        assert_eq!(GenericNackCode::MessageTooLarge as u8, 0x02);
        assert_eq!(GenericNackCode::OutOfMemory as u8, 0x03);
        assert_eq!(GenericNackCode::InvalidPayloadLength as u8, 0x04);
    }

    #[test]
    fn protocol_version_inverse_relationship() {
        // Version XOR inverse must equal 0xFF (per spec)
        assert_eq!(DEFAULT_PROTOCOL_VERSION ^ DEFAULT_PROTOCOL_VERSION_INV, 0xFF);
    }

    #[test]
    fn header_display_shows_readable_info() {
        let hdr = make_header(0x8001, 10);
        let s = format!("{}", hdr);
        assert!(s.contains("DiagnosticMessage"));
        assert!(s.contains("10")); // payload length
    }

    #[test]
    fn default_header_has_correct_version() {
        let hdr = DoipHeader::default();
        assert_eq!(hdr.version, 0x02);
        assert_eq!(hdr.inverse_version, 0xFD);
    }
}
