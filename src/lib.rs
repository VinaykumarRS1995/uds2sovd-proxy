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
//! A DoIP (Diagnostics over Internet Protocol) server library.
//! This crate provides a transport bridge between DoIP clients and an SOVD (Service-Oriented Vehicle Diagnostics) backend.
//!
//! ## What this library offers
//!
//! ## Crate Layout
//!
//! | Module       | Responsibility|
//! |--------------|----------------|
//! | [`config`]    | Configuration structs and providers |
//! | [`doip`]      | DoIP protocol handling (message parsing, serialization, etc.)|
//! | [`error`]       | Error types and handling utilities |
//! | [`proxy`]      | The `SovdProxy` trait and related types for interfacing with the SOVD backend |
//! | [`server`]     | The main server implementation, including the dispatcher and message handlers |
//!
//! ##  Request Flow
//!
//! ```text
//! How these layers fit together
//!
//!         Tester ( doipclient)
//!       │ TCP :13400                │ UDP :13400
//!       ▼                           ▼
//!  TcpTransport               UdpTransport
//!       │                           │
//!       └──────────────┬────────────┘
//!                      ▼
//!           Dispatcher<PayloadType> // This dispatcher routes messages to protocol-specific
//!                      |               handlers based on the DoIP message type
//!                      │
//!           Message Handlers (×8)
//!                      │
//!             SovdProxy (trait)
//!                      │
//!         ┌────────────┴────────────┐
//!      StubProxy              RealSovdProxy
//!      (NRC 0x11)             (SOVD REST API)
//!        current                future
//! ```
//! ## How to use
//!
//! 1. Implement the SovdProxy trait for your SOVD backend.
//! 2. Create a config (TOML file or in-memory).
//! 3. Build the server and run it.
//!
//! ## Public API
//!
//! Only six types are publicly exported. Everything else is `pub(crate)` or private.
//!
//! | Type | What it is |
//! |------|------------|
//! | [`server`] | starts and runs the DoIP server, manages TCP and UDP transports, and handles shutdown |
//! | `ServerConfig` | Configuration for the DoIP server |
//! | `ConfigProvider` | Trait for loading configuration from various sources (TOML, environment variables, etc.) |
//! | `DefaultConfigProvider` | A simple ConfigProvider that takes a ServerConfig directly (useful for testing) |
//! | `TomlConfigProvider` | A ConfigProvider that loads configuration from a TOML file |
//! | `SovdProxy` | Trait that defines the interface for forwarding UDS requests to an SOVD backend and returning responses |
//!
//!
//! ## System Boundaries
//! This crate is Responsible for:
//! - TCP and UDP DoIP communication
//! - Parsing and serializing DoIP messages
//! - Routing DoIP requests to handlers
//! - Managing transport-level sessions
//! - Forwarding UDS payloads through SovdProxy
//!
//! This crate is not Responsible for:
//! - UDS service execution
//! - Diagnostic business logic
//! - Security access algorithms
//!
//!  ## Current Status
//!
//! Implemented
//! - TCP DoIP Transport with basic message parsing and handling
//! - UDP Vechicle Discovery with basic request handling
//! - Message dispatching based on DoIP message types
//! - Diagnostic message forwarding to a StubProxy that returns NRC 0x11 (Service Not Supported) for all requests
//!
//! Future Work
//! - Full routing activation state machine implementation
//! - Producation SOVD backend integration (e.g., REST API client)
//! - Additional protocol validation
//!  
//! See `app/main.rs` for a working example and `app/sample-doip-server.toml` for
//! a reference configuration

pub mod config;
pub mod doip;
pub mod error;
pub mod proxy;
pub mod server;
