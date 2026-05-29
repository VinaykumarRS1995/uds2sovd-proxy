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

//! Configuration providers — load [`ServerConfig`](super::types::ServerConfig)
//! from different sources (in-memory, TOML file).

pub mod in_memory;
pub mod toml;
pub use self::toml as Toml_provider;

pub use in_memory::InMemoryConfigProvider;
pub use Toml_provider::TomlConfigProvider;