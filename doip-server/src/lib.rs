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
/// Core DoIP protocol types, codec, and wire-format handlers (ISO 13400-2:2019).
pub mod doip;
/// Error types and the crate-level [`Result`] alias.
pub mod error;
/// DoIP server configuration and session management.
pub mod server;
/// UDS service layer – bridges DoIP transport to ISO 14229-1 request/response handling.
pub mod uds;
pub use error::{DoipError, Result};
