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
//!
//! This module provides the core `DoIP` protocol types and codec for TCP/UDP communication.

/// Alive Check request/response handlers (ISO 13400-2:2019 §7.6).
pub mod alive_check;
/// Tokio codec framing for DoIP TCP streams.
pub mod codec;
/// Diagnostic Message request and acknowledgment handlers (ISO 13400-2:2019 §7.9).
pub mod diagnostic_message;
/// DoIP header parsing, validation, and serialization.
pub mod header;
/// DoIP payload type enumeration and dispatch.
pub mod payload;
/// Routing Activation request/response handlers (ISO 13400-2:2019 §7.7).
pub mod routing_activation;
/// Vehicle Identification request/response handlers (ISO 13400-2:2019 §7.5).
pub mod vehicle_id;

// Re-export core types and constants for convenient access.
// Constants are exported to allow external testing and custom DoIP message construction.
use bytes::{Bytes, BytesMut};
pub use codec::DoipCodec;
pub use header::{
    DEFAULT_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION_INV, DOIP_HEADER_LENGTH,
    DOIP_HEADER_VERSION_MASK, DOIP_VERSION_DEFAULT, DoipHeader, DoipMessage, GenericNackCode,
    MAX_DOIP_MESSAGE_SIZE, PROTOCOL_VERSION_V1, PROTOCOL_VERSION_V3, PayloadType,
};
pub use payload::DoipPayload;
use tracing::error;

use crate::DoipError;

/// Trait for `DoIP` message types that can be parsed from a raw payload slice.
///
/// Implement this for every message struct so callers can decode incoming
/// `DoIP` frames through a uniform interface.
pub trait DoipParseable: Sized {
    /// Parse a `DoIP` message from a raw payload byte slice.
    ///
    /// # Errors
    /// Returns [`DoipError`] if the payload is malformed or too short.
    fn parse(payload: &[u8]) -> crate::Result<Self>;
}

/// Trait for `DoIP` message types that can be serialized to a [`Bytes`] buffer.
///
/// Implement [`write_to`] with the wire-format logic. The default [`to_bytes`]
/// wraps it in a `BytesMut` and calls `freeze()`, so you never write that
/// boilerplate again.
pub trait DoipSerializable {
    /// Write the serialized wire-format bytes into `buf`.
    fn write_to(&self, buf: &mut BytesMut);

    /// Returns `Some(n)` when the size is known ahead of serialization,
    /// enabling [`to_bytes`] to pre-allocate the buffer and avoid incremental
    /// `BytesMut` reallocations for large messages.
    ///
    /// Returns `None` (the default) to indicate the size is not known in
    /// advance; [`to_bytes`] will then use a dynamically-growing buffer.
    /// Override this in your implementation whenever the encoded length is
    /// computable upfront.
    fn serialized_len(&self) -> Option<usize> {
        None
    }

    /// Serialize this message into a [`Bytes`] buffer.
    ///
    /// Pre-allocates the buffer when [`serialized_len`] returns `Some`.
    fn to_bytes(&self) -> Bytes {
        let mut buf = match self.serialized_len() {
            Some(n) => BytesMut::with_capacity(n),
            None => BytesMut::new(),
        };
        self.write_to(&mut buf);
        buf.freeze()
    }
}

/// Build a [`DoipError::PayloadTooShort`] from the given slice and expected length.
pub(crate) fn too_short(payload: &[u8], expected: usize) -> DoipError {
    DoipError::PayloadTooShort {
        expected,
        actual: payload.len(),
    }
}

/// Return `Err` if `payload` is shorter than `expected` bytes.
pub(crate) fn check_min_len(payload: &[u8], expected: usize) -> crate::Result<()> {
    if payload.len() < expected {
        Err(too_short(payload, expected))
    } else {
        Ok(())
    }
}

/// Extract the first `N` bytes of `payload` as a fixed-size array.
///
/// Logs an error and returns [`DoipError::PayloadTooShort`] when the slice
/// is shorter than `N` bytes, using `context` to identify the call site in the log.
pub(crate) fn parse_fixed_slice<const N: usize>(
    payload: &[u8],
    context: &str,
) -> crate::Result<[u8; N]> {
    payload
        .get(..N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| {
            let e = too_short(payload, N);
            error!(context, error = %e, "parse failed");
            e
        })
}
