// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! TOML-backed configuration provider.
//!
//! This provider loads server configuration from a TOML file
//! and deserializes it into a [`ServerConfig`] using Serde.
//!
//! This is the primary configuration provider intended for
//! production deployments.

use std::path::PathBuf;

use crate::config::types::ServerConfig;
use crate::config::{ConfigError, ConfigProvider};

/// A [`ConfigProvider`] implementation that loads configuration
/// from a TOML file.
///
/// This provider performs file I/O and deserialization on each
/// call to [`ConfigProvider::load`].
///
/// # Design Rationale
///
/// Configuration loading is separated from server startup to
/// keep the server independent of configuration sources.
///
/// This allows the same server implementation to be used with
/// TOML files, default configuration, or future configuration
/// backends.
pub struct TomlConfigProvider {
    /// Path to the TOML configuration file.    
    path: PathBuf,
}

impl TomlConfigProvider {
    /// Creates a provider that loads configuration from the specified TOML file.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ConfigProvider for TomlConfigProvider {
    ///Loads configuration from the TOML file specified in the provider.
    ///
    /// # Errors
    ///
    /// Returns a `ConfigError` if:
    /// - The TOML file cannot be read.
    /// - The TOML content cannot be deserialized into a `ServerConfig`.
    ///
    fn load(&self) -> Result<ServerConfig, ConfigError> {
        let content = std::fs::read_to_string(&self.path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }
}
