// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! UDS Module
//!
//! Provides the interface between `DoIP` transport and UDS processing.

#[cfg(any(test, feature = "test-handlers"))]
pub mod dummy_handler;
pub mod handler;
#[cfg(any(test, feature = "test-handlers"))]
pub mod stub_handler;

pub use handler::{service_id, UdsHandler, UdsRequest, UdsResponse};
