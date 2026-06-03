// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! # uds2sovd — DoIP Server Library
//!
//! A DoIP (Diagnostics over Internet Protocol) server library that accepts
//! UDS diagnostic requests from DoIP clients and forwards them to an SOVD backend.
//!
//! ## What this library offers
//!
//! config: Load server settings (bind addresses, ECU identity) from TOML or in-memory.
//! doip: DoIP protocol: message parsing, handlers for vehicle identification,
//!   routing activation, alive check, entity status, and diagnostic messages.
//! proxy: Forward UDS bytes to an SOVD backend. Implement the SovdProxy trait
//!   for your backend; StubProxy and MockProxy are provided for development and testing.
//! server: TCP/UDP transport layer with concurrent listeners and graceful shutdown.
//! error: Unified error type for protocol and I/O errors.
//!
//! ## How to use
//!
//! 1. Implement the SovdProxy trait for your SOVD backend.
//! 2. Create a config (TOML file or in-memory).
//! 3. Build the server and run it.
//!
//! See `app/main.rs` for a working example and `app/sample-doip-server.toml` for
//! a reference configuration

pub mod config;
pub mod doip;
pub mod error;
pub mod proxy;
pub mod server;
