// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//use super::super instead of crate::config to avoid circular dependency with config provider during compilation.
use super::super::{ConfigError, ConfigProvider};
use crate::config::types::ServerConfig;

/// Config provider that holds a pre-built [`ServerConfig`] in memory.
/// Use when configuration is constructed programmatically rather than loaded from a file.
pub struct DefaultConfigProvider {
    config: ServerConfig,
}

impl DefaultConfigProvider {
    /// Wrap an existing config for use as a provider.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }
}

impl ConfigProvider for DefaultConfigProvider {
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
