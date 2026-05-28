/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use crate::proxy::SovdProxyError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid header version: expected 0xFD, got {0:#x}")]
    InvalidHeaderVersion(u8),

    #[error("invalid inverse version: expected 0x02, got {0:#x}")]
    InvalidInverseVersion(u8),

    #[error("unknown DoIP payload type: {0:#06x}")]
    UnknownPayloadType(u16),

    #[error("invalid payload length: declared {declared}, got {actual}")]
    InvalidPayloadLength { declared: u32, actual: usize },

    #[error("payload too short: expected at least {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("payload length {0} exceeds maximum allowed size")]
    PayloadTooLarge(usize),

    #[error("SOVD proxy error: {0}")]
    Proxy(#[from] SovdProxyError),

    #[error("no matching entity for request")]
    NoMatch,
}
