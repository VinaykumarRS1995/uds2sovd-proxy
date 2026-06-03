// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP protocol and handler errors.
//!
//! Error variants map to either Generic Header NACK codes (ISO 13400-2 Table 18)
//! or silent discard behavior per the specification.

use crate::doip::message::DoipNackCode;
use crate::proxy::SovdProxyError;

/// DoIP protocol errors and handler failures.
///
/// Most variants map to Generic Header NACK codes sent to the client.
/// Special cases like `EIDNotMatched` and `VinNotMatched` trigger silent
/// discard per ISO 13400-2 §7.6.1 discovery behavior.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Protocol version byte doesn't match expected value (ISO 13400-2 §7.3).
    /// Connection should be closed after sending NACK.
    #[error("invalid header version: expected 0xFD, got {0:#x}")]
    InvalidHeaderVersion(u8),

    /// Inverse version byte doesn't match ~PROTOCOL_VERSION (ISO 13400-2 §7.3).
    /// Connection should be closed after sending NACK.
    #[error("invalid inverse version: expected 0x02, got {0:#x}")]
    InvalidInverseVersion(u8),

    #[error("unknown DoIP payload type: {0:#06x}")]
    UnknownPayloadType(u16),

    #[error("invalid payload length: expected {expected}, got {actual}")]
    InvalidPayloadLength { expected: u32, actual: usize },

    #[error("payload too short: expected at least {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("payload length {0} exceeds maximum allowed size")]
    PayloadTooLarge(usize),

    /// Payload received when none was expected (e.g., AliveCheck with data).
    #[error("unexpected payload: expected {expected} bytes, got {actual}")]
    UnexpectedPayload { expected: usize, actual: usize },

    #[error("SOVD proxy error: {0}")]
    Proxy(#[from] SovdProxyError),

    /// Discovery request EID doesn't match this entity's EID.
    /// Per ISO 13400-2 §7.6.1, entity remains silent (no NACK sent).
    #[error("no matching EID for request")]
    EIDNotMatched,

    /// Discovery request VIN doesn't match this entity's VIN.
    /// Per ISO 13400-2 §7.6.1, entity remains silent (no NACK sent).
    #[error("no matching VIN for request")]
    VinNotMatched,
}

impl Error {
    /// Maps this error to the appropriate Generic Header NACK code
    /// per ISO 13400-2 Table 18.
    ///
    /// # Special cases
    ///
    /// - `EIDNotMatched`/`VinNotMatched`: Return `IncorrectPattern` as defensive
    ///   fallback, though these errors should trigger silent discard in the transport
    ///   layer per ISO 13400-2 §7.6.1, not NACK generation.
    /// - `Proxy(_)`: Maps to `IncorrectPattern` until real proxy error handling is wired.
    pub fn nack_code(&self) -> DoipNackCode {
        match self {
            Error::InvalidHeaderVersion(_) | Error::InvalidInverseVersion(_) => {
                DoipNackCode::IncorrectPattern
            }
            Error::UnknownPayloadType(_) => DoipNackCode::UnknownPayloadType,
            Error::PayloadTooLarge(_) => DoipNackCode::MessageTooLarge,
            Error::InvalidPayloadLength { .. }
            | Error::PayloadTooShort { .. }
            | Error::UnexpectedPayload { .. } => DoipNackCode::InvalidPayloadLength,
            Error::Proxy(_) => DoipNackCode::IncorrectPattern,
            Error::EIDNotMatched | Error::VinNotMatched => DoipNackCode::IncorrectPattern,
        }
    }
}
