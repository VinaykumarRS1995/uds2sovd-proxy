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
//! Server Module
//!
//! `DoIP` server configuration and session management.

/// DoIP server configuration (addresses, timeouts, logical address, VIN, EID, GID).
pub mod config;
/// Top-level DoIP server runtime — wires TCP handler and session manager together.
pub mod doip_server;
/// Thread-safe session registry for active DoIP tester connections.
pub mod session;
/// TCP diagnostic handler — accept loop, routing activation, diagnostic message dispatch.
pub mod tcp_handler;
/// UDP vehicle-discovery handler (ISO 13400-2:2019 §8.3 – vehicle identification).
pub mod udp_handler;

pub use config::ServerConfig;
pub use doip_server::DoipServer;
pub use session::{Session, SessionManager};

// No unit tests: this file contains only module declarations and re-exports.
// config.rs and session.rs carry their own test suites.
