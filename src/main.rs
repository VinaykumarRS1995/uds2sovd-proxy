// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! `DoIP` Server - Async Implementation

use clap::Parser;
use doip_server::server::{DoipServer, ServerConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "doip-server")]
#[command(about = "DoIP Server (ISO 13400-2)", version)]
struct Args {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// TCP/UDP bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Port number
    #[arg(short, long, default_value = "13400")]
    port: u16,

    /// Logical address (hex)
    #[arg(short, long, default_value = "0x1000")]
    logical_address: String,

    /// VIN (17 characters)
    #[arg(long)]
    vin: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    let config = if let Some(path) = args.config {
        info!("Loading config from {:?}", path);
        ServerConfig::from_file(&path)?
    } else {
        let mut config = ServerConfig::default();

        let addr = format!("{}:{}", args.bind, args.port);
        config.tcp_addr = addr.parse()?;
        config.udp_addr = addr.parse()?;

        if let Some(la) = args.logical_address.strip_prefix("0x") {
            config.logical_address = u16::from_str_radix(la, 16)?;
        } else {
            config.logical_address = args.logical_address.parse()?;
        }

        if let Some(vin) = args.vin {
            let bytes = vin.as_bytes();
            if bytes.len() != 17 {
                anyhow::bail!("VIN must be exactly 17 characters");
            }
            config.vin.copy_from_slice(bytes);
        }

        config
    };

    info!("Starting DoIP server");
    info!("  TCP: {}", config.tcp_addr);
    info!("  UDP: {}", config.udp_addr);
    info!("  Logical Address: 0x{:04X}", config.logical_address);
    info!("  VIN: {}", String::from_utf8_lossy(&config.vin));

    let server = Arc::new(DoipServer::new(config));
    let server_handle = Arc::clone(&server);

    // Spawn signal handler for graceful shutdown
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received Ctrl+C, initiating shutdown...");
                server_handle.shutdown();
            }
            Err(e) => {
                tracing::error!("Failed to listen for Ctrl+C: {}", e);
            }
        }
    });

    server.run().await
}
