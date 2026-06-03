// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration loading errors.
//!
//! Separates file I/O errors from TOML parsing errors for clearer
//! error messages to users.

/// Errors that can occur during configuration loading.
///
/// Variants distinguish between:
/// - Missing/unreadable files (`FileRead`)
/// - Malformed TOML syntax or validation failures (`ParseError`)
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),

    #[error("Failed to parse TOML config: {0}")]
    ParseError(#[from] toml::de::Error),
}
