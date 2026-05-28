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

//! DoIP server library (ISO 13400-2) — proxies UDS diagnostics to a SOVD backend.
//!
//! This crate provides the protocol layer, transport layer, configuration, and
//! proxy interface. The binary entry point lives in `app/main.rs`.

pub mod config;
pub mod doip;
pub mod error;
pub mod proxy;
pub mod server;
