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

//! `DoIP` Server binary entry point.
//!
//! Reads configuration from a TOML file (or uses defaults), initialises
//! structured logging, and runs the `DoIP` server until it is shut down.
//!
//! # Usage
//!
//! ```text
//! doip-server [--config <PATH>]
//! ```

use std::sync::Arc;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

use doip_server::{
    server::{DoipServer, ServerConfig},
    uds::{UdsHandler, UdsRequest, UdsResponse},
};

/// Command-line arguments for the `DoIP` server binary.
#[derive(Parser, Debug)]
#[command(name = "doip-server", about = "Eclipse OpenSOVD DoIP server")]
struct Args {
    /// Path to the server TOML configuration file.
    /// If omitted, ISO 13400-2 defaults are used (127.0.0.1:13400).
    #[arg(short, long, value_name = "FILE")]
    config: Option<std::path::PathBuf>,
}

/// Minimal pass-through UDS handler used when no external handler is injected.
///
/// Returns a Negative Response Code `0x31` (requestOutOfRange) for every
/// request, signalling that no real ECU backend is connected.
///
/// Replace this with a real implementation when integrating the UDS2SOVD proxy.
#[derive(Clone)]
struct PassThroughHandler;

/// NRC 0x31 — requestOutOfRange (ISO 14229-1:2020 Table A.1)
const NRC_REQUEST_OUT_OF_RANGE: u8 = 0x31;
/// Negative response SID (ISO 14229-1:2020 §8.1)
const NEGATIVE_RESPONSE_SID: u8 = 0x7F;

impl UdsHandler for PassThroughHandler {
    fn handle(&self, req: UdsRequest) -> UdsResponse {
        let sid = req.service_id().unwrap_or(0x00);
        let payload =
            bytes::Bytes::from(vec![NEGATIVE_RESPONSE_SID, sid, NRC_REQUEST_OUT_OF_RANGE]);
        UdsResponse::new(req.target_address(), req.source_address(), payload)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging from RUST_LOG env var (default: info).
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    let config = if let Some(path) = args.config {
        info!(path = %path.display(), "loading server config");
        ServerConfig::from_file(&path)?
    } else {
        info!("no config file supplied, using ISO 13400-2 defaults");
        ServerConfig::default()
    };

    DoipServer::new(Arc::new(config), PassThroughHandler)
        .run()
        .await
}
