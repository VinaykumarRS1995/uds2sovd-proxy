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

use crate::config::ConfigProvider;
use crate::config::types::ServerConfig;

/// Config provider that holds a pre-built [`ServerConfig`] in memory.
/// Use when configuration is constructed programmatically rather than loaded from a file.
pub struct InMemoryConfigProvider {
    config: ServerConfig,
}

impl InMemoryConfigProvider {
    /// Wrap an existing config for use as a provider.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }
}

impl ConfigProvider for InMemoryConfigProvider {
    fn load(&self) -> ServerConfig {
        self.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_stored_config() {
        let config = ServerConfig::default();
        let provider = InMemoryConfigProvider::new(config);
        // load() should return a valid config without panicking
        let (_tcp, _udp, _ecu) = provider.load().into_parts();
    }
}
