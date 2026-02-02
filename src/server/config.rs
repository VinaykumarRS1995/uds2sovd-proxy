//! DoIP Server Configuration

use std::net::SocketAddr;
use std::path::Path;
use serde::Deserialize;

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
            tcp_addr: "0.0.0.0:13400".parse().unwrap(),
            udp_addr: "0.0.0.0:13400".parse().unwrap(),
            logical_address: 0x1000,
            vin: *b"DOIPSERVER0000001",
            eid: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
            gid: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            max_connections: 10,
            initial_inactivity_timeout_ms: 2000,
            general_inactivity_timeout_ms: 300_000,
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
    pub fn new(logical_address: u16) -> Self {
        Self {
            logical_address,
            ..Default::default()
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: ConfigFile = toml::from_str(&content)?;
        
        let mut config = Self::default();
        
        if let Some(server) = file.server {
            let bind = server.bind_address.as_deref().unwrap_or("0.0.0.0");
            let tcp_port = server.tcp_port.unwrap_or(13400);
            let udp_port = server.udp_port.unwrap_or(13400);
            
            config.tcp_addr = format!("{}:{}", bind, tcp_port).parse()?;
            config.udp_addr = format!("{}:{}", bind, udp_port).parse()?;
            
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

    pub fn with_vin(mut self, vin: [u8; 17]) -> Self {
        self.vin = vin;
        self
    }

    pub fn with_addresses(mut self, tcp: SocketAddr, udp: SocketAddr) -> Self {
        self.tcp_addr = tcp;
        self.udp_addr = udp;
        self
    }
}
