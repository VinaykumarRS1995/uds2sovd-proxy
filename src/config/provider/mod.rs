// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration loading infra
//!
//! This module provides abstraction and implementations for creating
//! [`ServerConfig`](super::types::ServerConfig) instances from different sources.
//!
//! # Design Rationale
//!
//! Configuration loading is separated from configuration usage.
//! The DoIP server consumes a fully constructed `\[`ServerConfig`]
//! and remains unaware of where configuration data originated.
//!
//! This enables:
//!
//! - TOML-based configuration for production deployments
//! - In-memory configuration for tests
//! - Future configuration sources (environment variables,
//!   remote configuration services, etc.)
//!
//! # Implementations
//!
//! - [`TomlConfigProvider`] loads configuration from TOML files.
//! - [`DefaultConfigProvider`] provides an in-memory configuration
//!   primarily intended for testing and examples.

pub mod default_config;
pub mod toml;

pub use default_config::DefaultConfigProvider;
pub use toml::TomlConfigProvider;
