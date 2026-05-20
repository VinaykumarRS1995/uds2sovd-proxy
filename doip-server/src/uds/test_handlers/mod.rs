/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Test-only UDS handlers for integration testing and demo purposes.
//!
//! Enabled when the `test-handlers` feature is active or in `#[cfg(test)]`.
//! Production deployments should use a real [`crate::uds::UdsHandler`] implementation.

/// Dummy ECU handler returning positive responses — for testing and demos.
pub mod dummy;

/// Stub handler returning configurable negative responses — for testing error paths.
pub mod stub;
