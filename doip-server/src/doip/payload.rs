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
//! Typed dispatch envelope for `DoIP` message payloads (ISO 13400-2:2019).
//!
//! [`DoipPayload`] is a strongly-typed enum that wraps every concrete payload
//! struct. Use [`DoipPayload::parse`] to decode a raw [`DoipMessage`] into
//! the correct variant in one step, instead of manually matching on
//! [`PayloadType`] throughout the codebase.
//!
//! # Example
//! ```no_run
//! # use doip_server::doip::{DoipMessage, DoipPayload};
//! # use doip_server::Result;
//! fn dispatch(msg: &DoipMessage) -> Result<()> {
//!     match DoipPayload::parse(msg)? {
//!         DoipPayload::DiagnosticMessage(m) => println!("UDS payload: {:?}", m),
//!         DoipPayload::AliveCheckRequest(_) => println!("Alive check received"),
//!         _ => {}
//!     }
//!     Ok(())
//! }
//! ```

use super::{
    DoipMessage, DoipParseable, GenericNackCode, PayloadType, alive_check, diagnostic_message,
    routing_activation, vehicle_id,
};
use crate::DoipError;
use crate::Result;

/// A fully-parsed `DoIP` message payload.
///
/// Each variant corresponds to one [`PayloadType`] and wraps the concrete
/// struct returned by its [`DoipParseable`] impl.
#[derive(Debug)]
pub enum DoipPayload {
    /// `0x0007` – Alive Check Request (zero-length payload)
    AliveCheckRequest(alive_check::AliveCheckRequest),
    /// `0x0008` – Alive Check Response
    AliveCheckResponse(alive_check::AliveCheckResponse),
    /// `0x0005` – Routing Activation Request
    RoutingActivationRequest(routing_activation::RoutingActivationRequest),
    /// `0x0006` – Routing Activation Response
    RoutingActivationResponse(routing_activation::RoutingActivationResponse),
    /// `0x8001` – Diagnostic Message (UDS data)
    DiagnosticMessage(diagnostic_message::DiagnosticMessage),
    /// `0x8002` – Diagnostic Message Positive Acknowledgement
    DiagnosticMessagePositiveAck(diagnostic_message::DiagnosticAck),
    /// `0x8003` – Diagnostic Message Negative Acknowledgement
    DiagnosticMessageNegativeAck(diagnostic_message::DiagnosticAck),
    /// `0x0001` – Vehicle Identification Request (no filter)
    VehicleIdentificationRequest(vehicle_id::VehicleIdRequest),
    /// `0x0002` – Vehicle Identification Request filtered by EID
    VehicleIdentificationRequestWithEid(vehicle_id::VehicleIdRequestWithEid),
    /// `0x0003` – Vehicle Identification Request filtered by VIN
    VehicleIdentificationRequestWithVin(vehicle_id::VehicleIdRequestWithVin),
    /// `0x0004` – Vehicle Identification Response / Announce
    VehicleIdentificationResponse(vehicle_id::VehicleIdResponse),
    /// `0x0000` – Generic `DoIP` Header Negative Acknowledgement
    GenericNack(GenericNackCode),
}

impl DoipPayload {
    /// Decode the payload of a [`DoipMessage`] into a typed [`DoipPayload`] variant.
    ///
    /// # Errors
    /// Returns [`DoipError::UnknownPayloadType`] when the `payload_type` field
    /// in the header does not map to a known [`PayloadType`] variant, or when
    /// the `DoIP` payload byte is not a recognized `GenericNackCode`.
    ///
    /// Returns a more specific [`DoipError`] (e.g. [`DoipError::PayloadTooShort`])
    /// when the payload bytes are present but malformed.
    pub fn parse(msg: &DoipMessage) -> Result<Self> {
        let payload = msg.payload().as_ref();

        let payload_type = msg
            .payload_type()
            .ok_or_else(|| DoipError::UnknownPayloadType(msg.header().payload_type()))?;

        match payload_type {
            PayloadType::AliveCheckRequest => Ok(Self::AliveCheckRequest(
                alive_check::AliveCheckRequest::parse(payload)?,
            )),
            PayloadType::AliveCheckResponse => Ok(Self::AliveCheckResponse(
                alive_check::AliveCheckResponse::parse(payload)?,
            )),
            PayloadType::RoutingActivationRequest => Ok(Self::RoutingActivationRequest(
                routing_activation::RoutingActivationRequest::parse(payload)?,
            )),
            PayloadType::RoutingActivationResponse => Ok(Self::RoutingActivationResponse(
                routing_activation::RoutingActivationResponse::parse(payload)?,
            )),
            PayloadType::DiagnosticMessage => Ok(Self::DiagnosticMessage(
                diagnostic_message::DiagnosticMessage::parse(payload)?,
            )),
            PayloadType::DiagnosticMessagePositiveAck => Ok(Self::DiagnosticMessagePositiveAck(
                diagnostic_message::DiagnosticAck::parse_positive(payload)?,
            )),
            PayloadType::DiagnosticMessageNegativeAck => Ok(Self::DiagnosticMessageNegativeAck(
                diagnostic_message::DiagnosticAck::parse_negative(payload)?,
            )),
            PayloadType::VehicleIdentificationRequest => Ok(Self::VehicleIdentificationRequest(
                vehicle_id::VehicleIdRequest::parse(payload)?,
            )),
            PayloadType::VehicleIdentificationRequestWithEid => {
                Ok(Self::VehicleIdentificationRequestWithEid(
                    vehicle_id::VehicleIdRequestWithEid::parse(payload)?,
                ))
            }
            PayloadType::VehicleIdentificationRequestWithVin => {
                Ok(Self::VehicleIdentificationRequestWithVin(
                    vehicle_id::VehicleIdRequestWithVin::parse(payload)?,
                ))
            }
            PayloadType::VehicleIdentificationResponse => Ok(Self::VehicleIdentificationResponse(
                vehicle_id::VehicleIdResponse::parse(payload)?,
            )),
            PayloadType::GenericNack => {
                let byte = payload.first().copied().ok_or(DoipError::PayloadTooShort {
                    expected: 1,
                    actual: 0,
                })?;
                let code = GenericNackCode::try_from(byte)
                    .map_err(|b| DoipError::UnknownPayloadType(u16::from(b)))?;
                Ok(Self::GenericNack(code))
            }
            PayloadType::DoipEntityStatusRequest
            | PayloadType::DoipEntityStatusResponse
            | PayloadType::DiagnosticPowerModeRequest
            | PayloadType::DiagnosticPowerModeResponse => {
                Err(DoipError::UnknownPayloadType(u16::from(payload_type)))
            }
        }
    }

    /// Return the [`PayloadType`] that corresponds to this payload variant.
    #[must_use]
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Self::AliveCheckRequest(_) => PayloadType::AliveCheckRequest,
            Self::AliveCheckResponse(_) => PayloadType::AliveCheckResponse,
            Self::RoutingActivationRequest(_) => PayloadType::RoutingActivationRequest,
            Self::RoutingActivationResponse(_) => PayloadType::RoutingActivationResponse,
            Self::DiagnosticMessage(_) => PayloadType::DiagnosticMessage,
            Self::DiagnosticMessagePositiveAck(_) => PayloadType::DiagnosticMessagePositiveAck,
            Self::DiagnosticMessageNegativeAck(_) => PayloadType::DiagnosticMessageNegativeAck,
            Self::VehicleIdentificationRequest(_) => PayloadType::VehicleIdentificationRequest,
            Self::VehicleIdentificationRequestWithEid(_) => {
                PayloadType::VehicleIdentificationRequestWithEid
            }
            Self::VehicleIdentificationRequestWithVin(_) => {
                PayloadType::VehicleIdentificationRequestWithVin
            }
            Self::VehicleIdentificationResponse(_) => PayloadType::VehicleIdentificationResponse,
            Self::GenericNack(_) => PayloadType::GenericNack,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn make_msg(payload_type: PayloadType, payload: impl Into<Bytes>) -> DoipMessage {
        DoipMessage::new(payload_type, payload.into())
    }

    #[test]
    fn alive_check_request_roundtrip() {
        let msg = make_msg(PayloadType::AliveCheckRequest, vec![]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::AliveCheckRequest(_)));
        assert_eq!(parsed.payload_type(), PayloadType::AliveCheckRequest);
    }

    #[test]
    fn alive_check_response_roundtrip() {
        let msg = make_msg(PayloadType::AliveCheckResponse, vec![0x0E, 0x80]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::AliveCheckResponse(_)));
    }

    #[test]
    fn routing_activation_request_roundtrip() {
        let payload = vec![0x0E, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00];
        let msg = make_msg(PayloadType::RoutingActivationRequest, payload);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::RoutingActivationRequest(_)));
    }

    #[test]
    fn routing_activation_response_roundtrip() {
        use crate::doip::DoipSerializable;
        let resp = routing_activation::RoutingActivationResponse::success(0x0E80, 0x1000);
        let msg = make_msg(PayloadType::RoutingActivationResponse, resp.to_bytes());
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::RoutingActivationResponse(_)));
    }

    #[test]
    fn generic_nack_roundtrip() {
        let msg = make_msg(PayloadType::GenericNack, vec![0x02]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::GenericNack(GenericNackCode::MessageTooLarge)
        ));
    }

    #[test]
    fn unknown_payload_type_error() {
        let msg = DoipMessage::with_raw_payload_type(0xFFFF, Bytes::new());
        let err = DoipPayload::parse(&msg).unwrap_err();
        assert!(matches!(err, crate::DoipError::UnknownPayloadType(0xFFFF)));
    }

    #[test]
    fn missing_alive_check_response_data_errors() {
        let msg = make_msg(PayloadType::AliveCheckResponse, vec![]);
        assert!(DoipPayload::parse(&msg).is_err());
    }

    #[test]
    fn payload_type_round_trips() {
        assert_eq!(
            DoipPayload::GenericNack(GenericNackCode::MessageTooLarge).payload_type(),
            PayloadType::GenericNack,
        );
    }

    #[test]
    fn diagnostic_message_roundtrip() {
        // SA=0x0E80, TA=0x1000, SID=0x10 (DiagnosticSessionControl), sub=0x01
        let payload = vec![0x0E, 0x80, 0x10, 0x00, 0x10, 0x01];
        let msg = make_msg(PayloadType::DiagnosticMessage, payload);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(parsed, DoipPayload::DiagnosticMessage(_)));
        assert_eq!(parsed.payload_type(), PayloadType::DiagnosticMessage);
    }

    #[test]
    fn diagnostic_positive_ack_roundtrip() {
        // SA=0x0E80, TA=0x1000, ack_code=0x00 (positive per ISO 13400-2:2019 Table 27)
        let payload = vec![0x0E, 0x80, 0x10, 0x00, 0x00];
        let msg = make_msg(PayloadType::DiagnosticMessagePositiveAck, payload);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::DiagnosticMessagePositiveAck(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::DiagnosticMessagePositiveAck
        );
    }

    #[test]
    fn diagnostic_negative_ack_roundtrip() {
        // SA=0x0E80, TA=0x1000, nack_code=0x03 (UnknownTargetAddress)
        let payload = vec![0x0E, 0x80, 0x10, 0x00, 0x03];
        let msg = make_msg(PayloadType::DiagnosticMessageNegativeAck, payload);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::DiagnosticMessageNegativeAck(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::DiagnosticMessageNegativeAck
        );
    }

    #[test]
    fn vehicle_id_request_roundtrip() {
        // VehicleIdentificationRequest carries no payload (ISO 13400-2:2019 §7.5.2)
        let msg = make_msg(PayloadType::VehicleIdentificationRequest, vec![]);
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::VehicleIdentificationRequest(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::VehicleIdentificationRequest
        );
    }

    #[test]
    fn vehicle_id_request_with_eid_roundtrip() {
        let eid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let msg = make_msg(
            PayloadType::VehicleIdentificationRequestWithEid,
            eid.to_vec(),
        );
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::VehicleIdentificationRequestWithEid(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::VehicleIdentificationRequestWithEid
        );
    }

    #[test]
    fn vehicle_id_request_with_vin_roundtrip() {
        let vin = *b"TESTVIN1234567890"; // 17 ASCII bytes per ISO 3779
        let msg = make_msg(
            PayloadType::VehicleIdentificationRequestWithVin,
            vin.to_vec(),
        );
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::VehicleIdentificationRequestWithVin(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::VehicleIdentificationRequestWithVin
        );
    }

    #[test]
    fn vehicle_id_response_roundtrip() {
        use crate::doip::DoipSerializable;
        let vin = *b"TESTVIN1234567890";
        let eid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let gid = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54];
        let resp = vehicle_id::Response::new(vin, 0x1000, eid, gid);
        let msg = make_msg(PayloadType::VehicleIdentificationResponse, resp.to_bytes());
        let parsed = DoipPayload::parse(&msg).unwrap();
        assert!(matches!(
            parsed,
            DoipPayload::VehicleIdentificationResponse(_)
        ));
        assert_eq!(
            parsed.payload_type(),
            PayloadType::VehicleIdentificationResponse
        );
    }

    #[test]
    fn entity_status_and_power_mode_return_unknown_error() {
        // These payload types are recognised by the header but not yet dispatched
        // in DoipPayload::parse — they must return UnknownPayloadType.
        for pt in [
            PayloadType::DoipEntityStatusRequest,
            PayloadType::DoipEntityStatusResponse,
            PayloadType::DiagnosticPowerModeRequest,
            PayloadType::DiagnosticPowerModeResponse,
        ] {
            let msg = make_msg(pt, vec![]);
            assert!(
                matches!(
                    DoipPayload::parse(&msg),
                    Err(crate::DoipError::UnknownPayloadType(_))
                ),
                "expected UnknownPayloadType for {pt:?}"
            );
        }
    }

    #[test]
    fn generic_nack_empty_payload_returns_error() {
        // GenericNack requires exactly 1 byte for the nack code
        let msg = make_msg(PayloadType::GenericNack, vec![]);
        assert!(matches!(
            DoipPayload::parse(&msg),
            Err(crate::DoipError::PayloadTooShort {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn alive_check_request_with_data_returns_error() {
        // AliveCheckRequest must have a zero-length payload (ISO 13400-2:2019 §7.6)
        let msg = make_msg(PayloadType::AliveCheckRequest, vec![0xDE, 0xAD]);
        assert!(matches!(
            DoipPayload::parse(&msg),
            Err(crate::DoipError::UnexpectedPayload { actual: 2 })
        ));
    }

    #[test]
    fn payload_type_covers_all_variants() {
        // Verify payload_type() returns the matching PayloadType for every variant
        let vin = *b"TESTVIN1234567890";
        let eid = [0x12u8; 6];
        let gid = [0xFEu8; 6];

        assert_eq!(
            DoipPayload::AliveCheckRequest(alive_check::Request).payload_type(),
            PayloadType::AliveCheckRequest
        );
        assert_eq!(
            DoipPayload::AliveCheckResponse(alive_check::Response::new(0x0E80)).payload_type(),
            PayloadType::AliveCheckResponse
        );
        assert_eq!(
            DoipPayload::VehicleIdentificationRequest(vehicle_id::Request).payload_type(),
            PayloadType::VehicleIdentificationRequest
        );
        assert_eq!(
            DoipPayload::VehicleIdentificationRequestWithEid(vehicle_id::RequestWithEid::new(eid))
                .payload_type(),
            PayloadType::VehicleIdentificationRequestWithEid
        );
        assert_eq!(
            DoipPayload::VehicleIdentificationRequestWithVin(vehicle_id::RequestWithVin::new(vin))
                .payload_type(),
            PayloadType::VehicleIdentificationRequestWithVin
        );
        assert_eq!(
            DoipPayload::VehicleIdentificationResponse(vehicle_id::Response::new(
                vin, 0x1000, eid, gid
            ))
            .payload_type(),
            PayloadType::VehicleIdentificationResponse
        );
    }
}
