// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::doip::constants::{INVERSE_VERSION, PROTOCOL_VERSION};

/// Generic DoIP header NACK codes (ISO 13400-2 §9.4, Table 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DoipNackCode {
    /// Header fields do not match the expected pattern (bad version or inverse byte).
    IncorrectPattern = 0x00,
    /// Payload type is not supported by this entity.
    UnknownPayloadType = 0x01,
    /// Message is too large to be processed.
    MessageTooLarge = 0x02,
    /// Server ran out of memory.
    OutOfMemory = 0x03,
    /// Payload length field does not match actual payload size.
    InvalidPayloadLength = 0x04,
}

impl From<DoipNackCode> for u8 {
    fn from(code: DoipNackCode) -> Self {
        code as u8
    }
}

// Connection identity

/// Unique identifier for a TCP session, assigned at connection accept time.
///
/// Distinct from DoIP logical address, which is negotiated during routing
/// activation and used for message routing within the diagnostic protocol.
#[derive(Debug)]
pub struct ConnectionId(uuid::Uuid);

impl ConnectionId {
    /// Generate a new random connection ID.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Payload types

/// Payload types valid on TCP connections (ISO 13400-2).
/// Compile-time type-safe: a UdpPayloadType value cannot be assigned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TcpPayloadType {
    GenericDoipHeaderNack = 0x0000,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DiagnosticMessage = 0x8001,
    DiagnosticMessagePositiveAck = 0x8002,
    DiagnosticMessageNegativeAck = 0x8003,
}

impl TryFrom<u16> for TcpPayloadType {
    type Error = u16;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0000 => Ok(Self::GenericDoipHeaderNack),
            0x0005 => Ok(Self::RoutingActivationRequest),
            0x0006 => Ok(Self::RoutingActivationResponse),
            0x0007 => Ok(Self::AliveCheckRequest),
            0x0008 => Ok(Self::AliveCheckResponse),
            0x8001 => Ok(Self::DiagnosticMessage),
            0x8002 => Ok(Self::DiagnosticMessagePositiveAck),
            0x8003 => Ok(Self::DiagnosticMessageNegativeAck),
            other => Err(other),
        }
    }
}

/// Payload types valid on UDP (ISO 13400-2).
/// Compile-time type-safe: a TcpPayloadType value cannot be assigned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum UdpPayloadType {
    GenericDoipHeaderNack = 0x0000,
    VehicleIdentificationRequest = 0x0001,
    VehicleIdentificationRequestWithEid = 0x0002,
    VehicleIdentificationRequestWithVin = 0x0003,
    VehicleAnnouncementResponse = 0x0004,
    DoipEntityStatusRequest = 0x4001,
    DoipEntityStatusResponse = 0x4002,
}

impl TryFrom<u16> for UdpPayloadType {
    type Error = u16;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0000 => Ok(Self::GenericDoipHeaderNack),
            0x0001 => Ok(Self::VehicleIdentificationRequest),
            0x0002 => Ok(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Ok(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Ok(Self::VehicleAnnouncementResponse),
            0x4001 => Ok(Self::DoipEntityStatusRequest),
            0x4002 => Ok(Self::DoipEntityStatusResponse),
            other => Err(other),
        }
    }
}

// Transport-typed requests

/// A request arriving over a TCP connection.
/// The payload type is compile-time restricted to [`TcpPayloadType`] values.
// TODO: Consider unifying TcpRequest/UdpRequest into a generic Request<P>.
#[derive(Debug)]
pub struct TcpRequest {
    payload_type: TcpPayloadType,
    payload: Vec<u8>,
}

impl TcpRequest {
    /// Create a TCP request from a validated payload type and raw bytes.
    pub fn new(payload_type: TcpPayloadType, payload: Vec<u8>) -> Self {
        Self {
            payload_type,
            payload,
        }
    }

    /// The raw payload bytes (no DoIP header).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A request arriving over UDP.
/// The payload type is compile-time restricted to [`UdpPayloadType`] values.
pub struct UdpRequest {
    payload_type: UdpPayloadType,
    payload: Vec<u8>,
}

impl UdpRequest {
    /// Create a UDP request from a validated payload type and raw bytes.
    pub fn new(payload_type: UdpPayloadType, payload: Vec<u8>) -> Self {
        Self {
            payload_type,
            payload,
        }
    }

    /// The raw payload bytes (no DoIP header).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

// Response

/// DoIP response: payload type + payload bytes.
/// Transport-agnostic — the same struct is used for TCP writes and UDP sends.
/// Call `to_bytes()` to get the full on-wire representation including the 8-byte header.
#[derive(Debug)]
pub struct Response {
    payload_type: u16,
    payload: Vec<u8>,
}

impl Response {
    /// Create a response with a raw payload type and payload bytes.
    pub fn new(payload_type: u16, payload: Vec<u8>) -> Self {
        Self {
            payload_type,
            payload,
        }
    }

    /// Build a GenericDoipHeaderNack response (ISO 13400-2 §9.4).
    /// NACK codes: 0x00=incorrect pattern, 0x01=unknown payload type,
    /// 0x02=message too large, 0x03=out of memory, 0x04=invalid payload length.
    ///
    pub fn doip_header_nack(code: DoipNackCode) -> Self {
        Self::new(0x0000, vec![u8::from(code)])
    }

    /// The numeric payload type for this response.
    pub fn payload_type(&self) -> u16 {
        self.payload_type
    }

    /// The raw payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Serialise into on-wire bytes: 8-byte DoIP generic header + payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload().len() as u32;
        let mut buf = Vec::with_capacity(crate::doip::constants::HEADER_LEN + self.payload().len());
        buf.push(PROTOCOL_VERSION);
        buf.push(INVERSE_VERSION);
        buf.extend_from_slice(&self.payload_type().to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(self.payload());
        buf
    }
}

// Payload-type extraction

/// Implemented by request types so the generic `Dispatcher` can extract the
/// payload type without knowing the concrete request type.
pub trait HasPayloadType<PayloadType> {
    fn payload_type(&self) -> PayloadType;
}

impl HasPayloadType<TcpPayloadType> for TcpRequest {
    fn payload_type(&self) -> TcpPayloadType {
        self.payload_type
    }
}

impl HasPayloadType<UdpPayloadType> for UdpRequest {
    fn payload_type(&self) -> UdpPayloadType {
        self.payload_type
    }
}

/// Infallible conversion — every enum variant has a defined `u16` value.
impl From<TcpPayloadType> for u16 {
    fn from(payload_type: TcpPayloadType) -> Self {
        payload_type as u16
    }
}

impl From<UdpPayloadType> for u16 {
    fn from(payload_type: UdpPayloadType) -> Self {
        payload_type as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nack_response_has_correct_payload_type_and_code() {
        let resp = Response::doip_header_nack(DoipNackCode::MessageTooLarge);
        assert_eq!(resp.payload_type(), 0x0000);
        assert_eq!(resp.payload(), &[0x02]);
    }

    #[test]
    fn response_to_bytes_has_correct_header() {
        let resp = Response::new(0x0004, vec![0xAA, 0xBB]);
        let bytes = resp.to_bytes();
        assert_eq!(bytes[0], 0xFD); // protocol version
        assert_eq!(bytes[1], 0x02); // inverse version
        assert_eq!(&bytes[2..4], &0x0004u16.to_be_bytes()); // payload type
        assert_eq!(&bytes[4..8], &2u32.to_be_bytes()); // payload length
        assert_eq!(&bytes[8..], &[0xAA, 0xBB]); // payload
    }

    #[test]
    fn tcp_payload_type_try_from_valid() {
        assert_eq!(
            TcpPayloadType::try_from(0x0005),
            Ok(TcpPayloadType::RoutingActivationRequest)
        );
        assert_eq!(
            TcpPayloadType::try_from(0x8001),
            Ok(TcpPayloadType::DiagnosticMessage)
        );
    }

    #[test]
    fn tcp_payload_type_try_from_invalid() {
        assert_eq!(TcpPayloadType::try_from(0xFFFF), Err(0xFFFF));
    }

    #[test]
    fn udp_payload_type_try_from_valid() {
        assert_eq!(
            UdpPayloadType::try_from(0x0001),
            Ok(UdpPayloadType::VehicleIdentificationRequest)
        );
        assert_eq!(
            UdpPayloadType::try_from(0x4001),
            Ok(UdpPayloadType::DoipEntityStatusRequest)
        );
    }

    #[test]
    fn udp_payload_type_try_from_invalid() {
        assert_eq!(UdpPayloadType::try_from(0x9999), Err(0x9999));
    }

    #[test]
    fn payload_type_into_u16_roundtrip() {
        let tcp: u16 = TcpPayloadType::DiagnosticMessage.into();
        assert_eq!(tcp, 0x8001);
        let udp: u16 = UdpPayloadType::DoipEntityStatusRequest.into();
        assert_eq!(udp, 0x4001);
    }
    #[test]
    fn response_to_bytes_empty_payload() {
        let resp = Response::new(0x0006, vec![]);
        let bytes = resp.to_bytes();
        assert_eq!(bytes.len(), 8); // header only, no payload
        assert_eq!(&bytes[4..8], &0u32.to_be_bytes());
    }
}
