// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Default configuration provider.
//!
//! This provider wraps an already constructed [`ServerConfig`] and
//! returns it on every call to [`ConfigProvider::load`].
//!
//! Unlike [`TomlConfigProvider`](super::toml::TomlConfigProvider),
//! this provider performs no file I/O and does not involve parsing or validation logic.
//!

use super::super::{ConfigError, ConfigProvider};
use crate::config::types::ServerConfig;

/// A [`ConfigProvider`] implementation backed by an default_config instance
/// [`ServerConfig`].
///
/// This provider is primarily intended for testing, examples,
/// and applications that construct configuration programmatically.
///
/// # Design Rationale
///
/// The configuration loading abstraction allows the server
/// to remain independent of configuration sources.
///
/// `DefaultConfigProvider` exists to support testing and
/// dependency injection without requiring file-system access.
pub struct DefaultConfigProvider {
    config: ServerConfig,
}

impl DefaultConfigProvider {
    /// Creates a provider that always returns the supplied
    /// configuration instance.    
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }
}

impl ConfigProvider for DefaultConfigProvider {
    /// Returns a clone of the stored configuration.
    ///
    /// This operation cannot fail because the configuration
    /// has already been constructed and validated.
    fn load(&self) -> Result<ServerConfig, ConfigError> {
        // Default config is always valid, so this never fails
        Ok(self.config.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_stored_config() {
        let config = ServerConfig::default();
        let provider = DefaultConfigProvider::new(config);
        // load() should return a valid config without panicking
        let loaded = provider
            .load()
            .expect("Default config should always be valid");
        let (_tcp, _udp, _ecu) = loaded.into_parts();
    }

    #[test]
    fn load_returns_identical_config_on_repeated_calls() {
        let config = ServerConfig::default();
        let provider = DefaultConfigProvider::new(config);
        let first = provider.load().expect("Default config should be valid");
        let second = provider.load().expect("Default config should be valid");
        // Ensures the provider is stateless and idempotent.
        assert_eq!(
            first.into_parts().0.address(),
            second.into_parts().0.address()
        );
    }
}
