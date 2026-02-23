// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! `DoIP` Protocol Implementation
//!
//! This module provides the core `DoIP` protocol types and codec for TCP/UDP communication.

pub mod alive_check;
pub mod diagnostic_message;
pub mod header_parser;
pub mod routing_activation;
pub mod vehicle_id;

// Re-export core types and constants for convenient access.
// Constants are exported to allow external testing and custom DoIP message construction.
pub use header_parser::{
    DoipCodec, DoipHeader, DoipMessage, GenericNackCode, ParseError, PayloadType, Result,
    DEFAULT_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION_INV, DOIP_HEADER_LENGTH,
    MAX_DOIP_MESSAGE_SIZE,
};
