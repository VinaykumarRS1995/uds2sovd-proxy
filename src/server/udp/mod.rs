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

//! UDP transport — recv loop for DoIP discovery and entity status messages.

pub mod handler;

use std::io;
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::Transport;
use crate::config::UdpConfig;
use crate::doip::UdpDispatcher;
use crate::doip::constants::UDP_RECV_BUF_SIZE;
use crate::doip::error::Error;
use handler::Handler;

/// UDP transport: binds a socket and dispatches one datagram at a time.
pub struct Udp {
    config: UdpConfig,
    handler: Handler,
}

impl Udp {
    /// Create a UDP transport with the given config and dispatcher.
    pub fn new(config: UdpConfig, dispatcher: UdpDispatcher) -> Self {
        Self {
            config,
            handler: Handler::new(Arc::new(dispatcher)),
        }
    }
}

impl Transport for Udp {
    async fn start(&self) -> Result<(), io::Error> {
        let socket = UdpSocket::bind(self.config.address()).await?;
        tracing::info!(address = %self.config.address(), "UDP server listening");

        let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((bytes_received, src_addr)) => {
                    match self.handler.handle(&buf[..bytes_received]) {
                        Ok(resp) => {
                            if let Err(err) = socket.send_to(&resp.to_bytes(), src_addr).await {
                                tracing::error!(error = %err, peer = %src_addr, "UDP send error");
                            }
                        }
                        Err(Error::NoMatch) => {
                            tracing::debug!(peer = %src_addr, "no matching entity, not responding");
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, peer = %src_addr, "UDP dispatch error");
                            let nack = crate::doip::message::Response::doip_header_nack(
                                crate::doip::message::nack_code(&err),
                            );
                            let _ = socket.send_to(&nack.to_bytes(), src_addr).await;
                        }
                    }
                }
                Err(err) => tracing::error!(error = %err, "UDP recv error"),
            }
        }
    }
}
