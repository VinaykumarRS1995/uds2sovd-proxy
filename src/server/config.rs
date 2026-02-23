// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! `DoIP` Server Configuration

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

// ============================================================================
// Default Configuration Constants (per ISO 13400-2 DoIP specification)
// ============================================================================

/// Default `DoIP` port for both TCP and UDP as defined in ISO 13400-2
const DEFAULT_DOIP_PORT: u16 = 13400;

/// Default bind address - listen on all network interfaces
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";

/// Default ECU logical address (`DoIP` entity address)
const DEFAULT_LOGICAL_ADDRESS: u16 = 0x0091;

/// Default Vehicle Identification Number (17 ASCII characters per ISO 3779)
const DEFAULT_VIN: &[u8; 17] = b"TESTVIN1234567890";

/// Default Entity Identification (6 bytes, typically MAC address)
const DEFAULT_EID: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

/// Default Group Identification (6 bytes)
const DEFAULT_GID: [u8; 6] = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54];

/// Maximum concurrent TCP connections allowed
const DEFAULT_MAX_CONNECTIONS: usize = 10;

/// Initial inactivity timeout in milliseconds (`T_TCP_Initial` per ISO 13400-2: 2 seconds)
const DEFAULT_INITIAL_INACTIVITY_TIMEOUT_MS: u64 = 2_000;

/// General inactivity timeout in milliseconds (`T_TCP_General` per ISO 13400-2: 5 minutes)
const DEFAULT_GENERAL_INACTIVITY_TIMEOUT_MS: u64 = 300_000;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub logical_address: u16,
    pub vin: [u8; 17],
    pub eid: [u8; 6],
    pub gid: [u8; 6],
    pub max_connections: usize,
    pub initial_inactivity_timeout_ms: u64,
    pub general_inactivity_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_DOIP_PORT)),
            udp_addr: SocketAddr::from(([0, 0, 0, 0], DEFAULT_DOIP_PORT)),
            logical_address: DEFAULT_LOGICAL_ADDRESS,
            vin: *DEFAULT_VIN,
            eid: DEFAULT_EID,
            gid: DEFAULT_GID,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            initial_inactivity_timeout_ms: DEFAULT_INITIAL_INACTIVITY_TIMEOUT_MS,
            general_inactivity_timeout_ms: DEFAULT_GENERAL_INACTIVITY_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    server: Option<ServerSection>,
    vehicle: Option<VehicleSection>,
    timeouts: Option<TimeoutSection>,
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    tcp_port: Option<u16>,
    udp_port: Option<u16>,
    bind_address: Option<String>,
    max_connections: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct VehicleSection {
    logical_address: Option<u16>,
    vin: Option<String>,
    eid: Option<String>,
    gid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TimeoutSection {
    initial_inactivity_ms: Option<u64>,
    general_inactivity_ms: Option<u64>,
}

impl ServerConfig {
    #[must_use]
    pub fn new(logical_address: u16) -> Self {
        Self {
            logical_address,
            ..Default::default()
        }
    }

    /// Load configuration from TOML file
    ///
    /// # Errors
    /// Returns error if file cannot be read, parsed, or contains invalid values
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: ConfigFile = toml::from_str(&content)?;

        let mut config = Self::default();

        if let Some(server) = file.server {
            let bind = server
                .bind_address
                .as_deref()
                .unwrap_or(DEFAULT_BIND_ADDRESS);
            let tcp_port = server.tcp_port.unwrap_or(DEFAULT_DOIP_PORT);
            let udp_port = server.udp_port.unwrap_or(DEFAULT_DOIP_PORT);

            config.tcp_addr = format!("{bind}:{tcp_port}").parse()?;
            config.udp_addr = format!("{bind}:{udp_port}").parse()?;

            if let Some(max) = server.max_connections {
                config.max_connections = max;
            }
        }

        if let Some(vehicle) = file.vehicle {
            if let Some(addr) = vehicle.logical_address {
                config.logical_address = addr;
            }
            if let Some(vin) = vehicle.vin {
                config.vin = Self::parse_vin(&vin)?;
            }
            if let Some(eid) = vehicle.eid {
                config.eid = Self::parse_hex_array(&eid)?;
            }
            if let Some(gid) = vehicle.gid {
                config.gid = Self::parse_hex_array(&gid)?;
            }
        }

        if let Some(timeouts) = file.timeouts {
            if let Some(t) = timeouts.initial_inactivity_ms {
                config.initial_inactivity_timeout_ms = t;
            }
            if let Some(t) = timeouts.general_inactivity_ms {
                config.general_inactivity_timeout_ms = t;
            }
        }

        Ok(config)
    }

    fn parse_vin(s: &str) -> anyhow::Result<[u8; 17]> {
        let bytes = s.as_bytes();
        if bytes.len() != 17 {
            anyhow::bail!("VIN must be exactly 17 characters");
        }
        let mut vin = [0u8; 17];
        vin.copy_from_slice(bytes);
        Ok(vin)
    }

    fn parse_hex_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
        let s = s.trim_start_matches("0x").replace([':', '-', ' '], "");
        let bytes = hex::decode(&s)?;
        if bytes.len() != N {
            anyhow::bail!("Expected {} bytes, got {}", N, bytes.len());
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    #[must_use]
    pub fn with_vin(mut self, vin: [u8; 17]) -> Self {
        self.vin = vin;
        self
    }

    #[must_use]
    pub fn with_addresses(mut self, tcp: SocketAddr, udp: SocketAddr) -> Self {
        self.tcp_addr = tcp;
        self.udp_addr = udp;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();

        assert_eq!(config.tcp_addr.port(), DEFAULT_DOIP_PORT);
        assert_eq!(config.udp_addr.port(), DEFAULT_DOIP_PORT);
        assert_eq!(config.logical_address, DEFAULT_LOGICAL_ADDRESS);
        assert_eq!(config.vin, *DEFAULT_VIN);
        assert_eq!(config.eid, DEFAULT_EID);
        assert_eq!(config.gid, DEFAULT_GID);
        assert_eq!(config.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            config.initial_inactivity_timeout_ms,
            DEFAULT_INITIAL_INACTIVITY_TIMEOUT_MS
        );
        assert_eq!(
            config.general_inactivity_timeout_ms,
            DEFAULT_GENERAL_INACTIVITY_TIMEOUT_MS
        );
    }

    #[test]
    fn test_new_with_logical_address() {
        let config = ServerConfig::new(0x1234);

        assert_eq!(config.logical_address, 0x1234);
        assert_eq!(config.tcp_addr.port(), DEFAULT_DOIP_PORT);
    }

    #[test]
    fn test_parse_vin_valid() {
        let result = ServerConfig::parse_vin("WVWZZZ3CZWE123456");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 17);
    }

    #[test]
    fn test_parse_vin_invalid_length() {
        let result = ServerConfig::parse_vin("SHORTVIN");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_array_valid() {
        let result: anyhow::Result<[u8; 6]> = ServerConfig::parse_hex_array("00:1A:2B:3C:4D:5E");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    }

    #[test]
    fn test_parse_hex_array_with_0x_prefix() {
        let result: anyhow::Result<[u8; 6]> = ServerConfig::parse_hex_array("0x001A2B3C4D5E");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_hex_array_invalid_length() {
        let result: anyhow::Result<[u8; 6]> = ServerConfig::parse_hex_array("00:1A:2B");
        assert!(result.is_err());
    }

    #[test]
    fn test_with_vin_builder() {
        let new_vin = *b"NEWVIN12345678901";
        let config = ServerConfig::default().with_vin(new_vin);

        assert_eq!(config.vin, new_vin);
    }

    #[test]
    fn test_with_addresses_builder() {
        let tcp: SocketAddr = "192.168.1.1:13400".parse().unwrap();
        let udp: SocketAddr = "192.168.1.1:13401".parse().unwrap();
        let config = ServerConfig::default().with_addresses(tcp, udp);

        assert_eq!(config.tcp_addr, tcp);
        assert_eq!(config.udp_addr, udp);
    }
}
