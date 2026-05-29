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

//! Per-connection session: owns a [`ConnectionSlot`], drives the I/O loop,
//! and dispatches parsed frames to handlers.

pub(super) mod manager;
pub(super) mod slot;

pub(super) use manager::SessionManager;
pub(super) use slot::ConnectionSlot;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::doip::TcpDispatcher;
use crate::doip::message::{Response, TcpRequest};
use crate::server::tcp::framer::Framer;

/// Represents an accepted TCP connection.
///
/// Owns the `ConnectionSlot` (RAII counter decrement on drop). When `run()` completes
/// the slot is dropped, automatically decrementing the active session counter.
pub(super) struct Session {
    slot: ConnectionSlot,
}

impl Session {
    /// Create a session that owns the given connection slot.
    pub(super) fn new(slot: ConnectionSlot) -> Self {
        Self { slot }
    }

    /// Drive the session I/O loop.
    ///
    /// Consumes `self` — when this future completes (clean close, read error, or
    /// write error) the slot is dropped, automatically decrementing the session counter.
    pub(crate) async fn run(
        self,
        mut stream: TcpStream,
        dispatcher: Arc<TcpDispatcher>,
        buf_size: usize,
    ) {
        let id = &self.slot.id();
        let mut framer = Framer::new();
        let mut buf = vec![0u8; buf_size];

        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(id = %id, "client disconnected");
                    break;
                }
                Ok(bytes_read) => {
                    for frame_result in framer.feed(&buf[..bytes_read]) {
                        match frame_result {
                            Ok(frame) => {
                                // TODO: Consider creating TcpRequest directly from the buffer to avoid the intermediate Frame.
                                let (payload_type, payload) = frame.into_parts();
                                let req = TcpRequest::new(payload_type, payload);
                                match dispatcher.dispatch(req) {
                                    Ok(resp) => {
                                        if let Err(err) = stream.write_all(&resp.to_bytes()).await {
                                            tracing::error!(id = %id, error = %err, "write error");
                                            return;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::warn!(id = %id, error = %err, "dispatch error");
                                        let nack = Response::doip_header_nack(
                                            crate::doip::message::nack_code(&err),
                                        );
                                        let _ = stream.write_all(&nack.to_bytes()).await;
                                    }
                                }
                            }
                            Err(err) => {
                                tracing::warn!(id = %id, error = %err, "framing error");
                                let nack = Response::doip_header_nack(
                                    crate::doip::message::nack_code(&err),
                                );
                                let _ = stream.write_all(&nack.to_bytes()).await;
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(id = %id, error = %err, "read error");
                    // TODO: propagate error to caller instead of silently disconnecting
                    break;
                }
            }
        }
        // self drops here → slot drops → counter decremented
    }
}
