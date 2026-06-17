// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration subsystem error types.
//!
//! These errors represent failures that can occur while loading
//! and deserializing server configuration.
//!
//! Errors are categorized by source to provide clear diagnostics
//! to users and simplify troubleshooting.

/// Errors produced while loading server configuration.
///
/// The error variants preserve the original failure source,
/// allowing callers to distinguish between file access failures
/// and configuration deserialization failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    ///Failed to read the TOML configuration file.    
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),

    ///Failed to parse the TOML configuration content.
    #[error("Failed to parse TOML config: {0}")]
    ParseError(#[from] toml::de::Error),
}
