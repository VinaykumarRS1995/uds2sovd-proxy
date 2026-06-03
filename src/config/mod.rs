// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Server configuration: types, defaults, and pluggable providers.

pub mod defaults;
pub mod error;
pub mod provider;
pub mod types;

pub use error::ConfigError;
pub use provider::{DefaultConfigProvider, TomlConfigProvider};
pub use types::{EcuConfig, ServerConfig, TcpConfig, UdpConfig};

/// Trait for loading server configuration from any source.
pub trait ConfigProvider {
    /// Load and return a complete [`ServerConfig`].
    /// Returns an error if the configuration cannot be loaded or parsed.
    fn load(&self) -> Result<ServerConfig, ConfigError>;
}
