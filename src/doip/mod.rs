//! DoIP Protocol Implementation
//!
//! This module provides the core DoIP protocol types and codec for TCP/UDP communication.

pub mod header_parser;
pub mod routing_activation;
pub mod diagnostic_message;
pub mod vehicle_id;
pub mod alive_check;

pub use header_parser::{
    DoipCodec, DoipHeader, DoipMessage, GenericNackCode, ParseError, PayloadType, Result,
    DEFAULT_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION_INV, DOIP_HEADER_LENGTH,
    MAX_DOIP_MESSAGE_SIZE,
};
