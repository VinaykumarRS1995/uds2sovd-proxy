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

pub mod error;
#[cfg(test)]
pub mod mock;
pub mod stub;

pub use error::SovdProxyError;

/// Translates raw UDS request bytes into raw UDS response bytes by forwarding
/// the request to the SOVD diagnostic system.
///
/// # Contract
///
/// - `uds_request` contains only UDS service-layer bytes — no DoIP framing.
/// - On success the returned `Vec<u8>` is the raw UDS response from SOVD.
/// - On failure a [`SovdProxyError`] describes why the proxy could not produce
///   a response.
///
/// # Implementations
///
/// | Type | Purpose |
/// |  |   |
/// | [`stub::StubProxy`] | Returns NRC 0x11 (serviceNotSupported). Use until the real SOVD backend is ready. |
/// | [`mock::MockProxy`] | Loopback — echoes the request. Used in unit/integration tests. |
///
/// The real implementation (provided separately) will forward requests to a
/// SOVD server over the vehicle network.
pub trait SovdProxy: Send + Sync {
    fn forward(&self, uds_request: &[u8]) -> Result<Vec<u8>, SovdProxyError>;
}
