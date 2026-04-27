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

//! `DoipServer` — top-level runtime that wires UDP and TCP handlers together.
//!
//! ```no_run
//! use std::sync::Arc;
//! use doip_server::server::{DoipServer, ServerConfig};
//! use doip_server::uds::{UdsHandler, UdsRequest, UdsResponse};
//!
//! #[derive(Clone)]
//! struct MyHandler;
//! impl UdsHandler for MyHandler {
//!     fn handle(&self, req: UdsRequest) -> UdsResponse {
//!         UdsResponse::new(req.target_address(), req.source_address(), req.payload().clone())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Arc::new(ServerConfig::default());
//!     DoipServer::new(config, MyHandler).run().await
//! }
//! ```

use std::sync::Arc;

use tracing::info;

use super::{ServerConfig, SessionManager, tcp_handler};
use crate::uds::UdsHandler;

/// Top-level `DoIP` server runtime.
///
/// Holds the shared [`ServerConfig`] and [`SessionManager`] and starts both
/// the UDP vehicle-discovery listener and the TCP diagnostic listener when
/// [`run()`](DoipServer::run) is called.
pub struct DoipServer<H> {
    config: Arc<ServerConfig>,
    sessions: Arc<SessionManager>,
    handler: H,
}

impl<H> DoipServer<H>
where
    H: UdsHandler + Clone + Send + Sync + 'static,
{
    /// Create a new `DoipServer` with the given configuration and UDS handler.
    #[must_use]
    pub fn new(config: Arc<ServerConfig>, handler: H) -> Self {
        Self {
            config,
            sessions: SessionManager::new(),
            handler,
        }
    }

    /// Start the TCP diagnostic listener and run until it returns an error.
    ///
    /// The UDP vehicle-discovery listener is wired in after `feat/udp-handler`
    /// merges (where `udp_handler::run` is defined). At that point this method
    /// will use `tokio::try_join!` to run both concurrently.
    ///
    /// # Errors
    ///
    /// Returns an [`anyhow::Error`] if the TCP listener fails to bind or
    /// encounters an unrecoverable I/O error.
    pub async fn run(self) -> anyhow::Result<()> {
        info!(
            tcp = %self.config.tcp_addr(),
            udp = %self.config.udp_addr(),
            "DoIP server starting (TCP only; UDP handler added in feat/udp-handler)"
        );

        tcp_handler::run(self.config, self.sessions, self.handler)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::uds::{UdsRequest, UdsResponse};

    #[derive(Clone)]
    struct EchoHandler;
    impl UdsHandler for EchoHandler {
        fn handle(&self, req: UdsRequest) -> UdsResponse {
            UdsResponse::new(
                req.target_address(),
                req.source_address(),
                req.payload().clone(),
            )
        }
    }

    #[test]
    fn doip_server_new_creates_empty_sessions() {
        let config = Arc::new(ServerConfig::default());
        let server = DoipServer::new(Arc::clone(&config), EchoHandler);
        assert_eq!(server.sessions.session_count(), 0);
    }

    #[test]
    fn doip_server_uses_provided_config() {
        let config = Arc::new(ServerConfig::new(0xE000));
        let server = DoipServer::new(Arc::clone(&config), EchoHandler);
        assert_eq!(server.config.logical_address(), 0xE000);
    }
}
