// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Transport layer — TCP and UDP servers that speak DoIP on the wire.

pub mod tcp;
pub mod udp;

use std::io;
use tcp::Tcp;
use udp::Udp;

/// Lifecycle interface shared by the TCP and UDP transports.
//
// Justification: This trait is only used with concrete types (Tcp, Udp),
// never as `dyn Transport`, so object-safety is not required.
//
// # TODO: Graceful Shutdown
//
// Currently only `start()` is provided. Graceful shutdown with `stop()` method is intentionally
// omitted to avoid premature complexity. Current behavior:
//
// - Server runs until Ctrl+C (SIGINT)
// - Active connections drop immediately
// - No graceful cleanup of in-flight requests
//
// Future improvement: Add ServerHandle with shutdown() method that:
// 1. Signals transports to stop accepting new connections
// 2. Waits for active connections to complete (with timeout)
// 3. Returns when all resources are cleaned up
#[allow(async_fn_in_trait)]
pub trait Transport: Send + Sync {
    async fn start(&self) -> Result<(), io::Error>;
}

/// Top-level server owning both transports.
///
/// DoIP is defined as exactly one TCP and one UDP transport (ISO 13400-2).
pub struct Server {
    tcp: Tcp,
    udp: Udp,
}

impl Server {
    /// Create a server owning both transports.
    pub fn new(tcp: Tcp, udp: Udp) -> Self {
        Self { tcp, udp }
    }

    /// Run both transports concurrently. Shuts down gracefully on SIGINT(SIGTERM will also be handled in the future).
    pub async fn start(&self) -> Result<(), io::Error> {
        tokio::try_join!(self.tcp.start(), self.udp.start())?;
        Ok(())
    }
}
