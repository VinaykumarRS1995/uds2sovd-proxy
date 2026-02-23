// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! `DoIP` Server

mod config;
mod session;
mod tcp_handler;
mod udp_handler;

pub use config::ServerConfig;
pub use session::{Session, SessionManager, SessionState};
pub use tcp_handler::TcpHandler;
pub use udp_handler::UdpHandler;

use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing::{error, info, warn};

#[cfg(any(test, feature = "test-handlers"))]
use crate::uds::dummy_handler::DummyEcuHandler;
use crate::uds::UdsHandler;

pub struct DoipServer<H: UdsHandler + 'static> {
    config: Arc<ServerConfig>,
    sessions: Arc<SessionManager>,
    uds_handler: Arc<H>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Convenience constructor using `DummyEcuHandler`.
///
/// Only available with the `test-handlers` feature or in tests.
/// For production, use `DoipServer::with_handler()` with a real UDS handler.
#[cfg(any(test, feature = "test-handlers"))]
impl DoipServer<DummyEcuHandler> {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        Self::with_handler(config, DummyEcuHandler::new())
    }
}

impl<H: UdsHandler + 'static> DoipServer<H> {
    pub fn with_handler(config: ServerConfig, handler: H) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config: Arc::new(config),
            sessions: SessionManager::new(),
            uds_handler: Arc::new(handler),
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Run the `DoIP` server
    ///
    /// # Errors
    ///
    /// Returns an error if socket binding fails or other I/O errors occur.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Starting DoIP server");
        info!("  Logical address: 0x{:04X}", self.config.logical_address);
        info!("  VIN: {}", String::from_utf8_lossy(&self.config.vin));
        info!("  TCP: {}", self.config.tcp_addr);
        info!("  UDP: {}", self.config.udp_addr);

        let udp_socket = UdpSocket::bind(self.config.udp_addr).await?;
        info!("UDP socket bound to {}", self.config.udp_addr);

        let tcp_listener = TcpListener::bind(self.config.tcp_addr).await?;
        info!("TCP listener bound to {}", self.config.tcp_addr);

        // Spawn UDP handler
        let udp_handler = UdpHandler::new(Arc::clone(&self.config));
        let mut udp_shutdown = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = udp_handler.run(udp_socket) => {}
                _ = udp_shutdown.changed() => {
                    info!("UDP handler shutting down");
                }
            }
        });

        // TCP accept loop with shutdown
        let mut shutdown = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                result = tcp_listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            // Enforce max_connections limit (DoS protection per ISO 13400-2)
                            if self.sessions.session_count() >= self.config.max_connections {
                                warn!(
                                    "Connection rejected from {}: max_connections ({}) reached",
                                    peer_addr, self.config.max_connections
                                );
                                drop(stream);
                                continue;
                            }

                            info!("New TCP connection from {}", peer_addr);
                            let handler = TcpHandler::new(
                                Arc::clone(&self.config),
                                Arc::clone(&self.sessions),
                                Arc::clone(&self.uds_handler),
                            );
                            tokio::spawn(async move {
                                handler.handle_connection(stream).await;
                            });
                        }
                        Err(e) => {
                            error!("TCP accept error: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    warn!("Server shutting down");
                    break;
                }
            }
        }

        info!("Server stopped");
        Ok(())
    }
}
