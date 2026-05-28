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

use std::path::PathBuf;

use crate::config::ConfigProvider;
use crate::config::types::ServerConfig;

/// Config provider that loads a [`ServerConfig`] from a TOML file.
pub struct TomlConfigProvider {
    path: PathBuf,
}

impl TomlConfigProvider {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl ConfigProvider for TomlConfigProvider {
    fn load(&self) -> ServerConfig {
        let content = std::fs::read_to_string(&self.path)
            .unwrap_or_else(|e| panic!("Failed to read config file {:?}: {}", self.path, e));
        toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse config file {:?}: {}", self.path, e))
    }
}
