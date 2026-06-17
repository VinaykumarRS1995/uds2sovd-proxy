// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration subsystem for the DoIP server.
//!
//! This module defines the configuration model, Configuration loading abstraction,
//! and provider implementations used by the DoIP server.
//!
//! # Design Rationale
//!
//! Configuration loading is separted from configuration usage. The DoIP server consumes a fully constructed [`ServerConfig`]
//!
//! ```text
//! Configuration Source
//! │
//! ▼
//! ConfigProvider
//! │
//! ▼
//! ServerConfig
//! │
//! ▼
//! Server
//! ```
//!
//! This separation allows the same server implementation to be used with different configuration sources, such as:
//! - TOML files for production deployments
//! - Default configuration for tests and examples
//! - Future configuration sources (environment variables, remote configuration services, etc.)

pub mod defaults;
pub mod error;
pub mod provider;
pub mod types;

pub use error::ConfigError;
pub use provider::{DefaultConfigProvider, TomlConfigProvider};
pub use types::{EcuConfig, ServerConfig, TcpConfig, UdpConfig};

/// # Design Rationale
///
/// The DoIP server requires a fully validated configuration
/// before startup. By introducing a configuration provider
/// abstraction, the server remains independent of how
/// configuration is obtained.
///
/// This enables:
///
/// - TOML-based configuration for production deployments
/// - In-memory configuration for tests
/// - Future configuration sources without modifying server code
///
/// Abstraction for loading server configuration.
///
/// Implementations may load configuration from files,
/// Default structures, environment variables, or other
/// configuration backends.
///
/// The server depends on this trait rather than concrete
/// configuration sources, allowing configuration loading
/// concerns to remain isolated from server startup logic.
pub trait ConfigProvider {
    /// Loads and returns a complete [`ServerConfig`].
    ///
    /// # Errors
    ///
    ///Returns [`ConfigError`] if configuration loading fails..
    fn load(&self) -> Result<ServerConfig, ConfigError>;
}
