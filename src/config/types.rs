// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::net::SocketAddr;

use serde::Deserialize;

use super::defaults;
use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};

/// Top-level server configuration, split into TCP, UDP, and ECU sections.
///
///Private fields
///
/// Fields are private and accessed via `into_parts()` to:
/// - Force explicit destructuring of config sections
/// - Prevent accidental mixing of TCP/UDP/ECU settings
/// - Make it obvious in calling code which config section is being used
///
/// # Serde behavior
///
/// `#[serde(default)]` allows partial TOML files — missing sections use Default.
/// Users only specify what they want to change from defaults.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    tcp: TcpConfig,
    udp: UdpConfig,
    ecu: EcuConfig,
}

impl ServerConfig {
    /// Destructure into the three sub-configs.
    pub fn into_parts(self) -> (TcpConfig, UdpConfig, EcuConfig) {
        (self.tcp, self.udp, self.ecu)
    }
}

/// TCP transport settings: listen address, connection limits, buffer size.
///
/// Using #[serde(default)] allows omitting fields in TOML — they'll use Default values.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TcpConfig {
    address: SocketAddr,
    max_connections: usize,
    logical_address: LogicalAddress,
    read_buffer_size: usize,
}

impl TcpConfig {
    /// TCP listen address (e.g. `127.0.0.1:13400`).
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Maximum number of concurrent TCP sessions.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// This entity's DoIP logical address.
    pub fn logical_address(&self) -> LogicalAddress {
        self.logical_address
    }

    /// TCP read buffer size in bytes.
    pub fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }
}

/// UDP transport settings: listen address and logical address.
///
/// Using #[serde(default)] allows omitting fields in TOML — they'll use Default values.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UdpConfig {
    address: SocketAddr,
    logical_address: LogicalAddress,
}

impl UdpConfig {
    /// UDP listen address (e.g. `0.0.0.0:13400`).
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// This entity's DoIP logical address.
    pub fn logical_address(&self) -> LogicalAddress {
        self.logical_address
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            address: defaults::TCP_ADDRESS,
            max_connections: defaults::MAX_CONNECTIONS,
            logical_address: defaults::LOGICAL_ADDRESS,
            read_buffer_size: defaults::READ_BUFFER_SIZE,
        }
    }
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            address: defaults::UDP_ADDRESS,
            logical_address: defaults::LOGICAL_ADDRESS,
        }
    }
}

/// ECU identity settings: VIN, EID, and GID used in vehicle identification responses.
///
/// Note: No #[serde(default)] here since VIN/EID are required configuration parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct EcuConfig {
    vin: Vin,
    eid: Eid,
    gid: Gid,
}

impl EcuConfig {
    /// Create a new ECU config from the given identity fields.
    pub fn new(vin: Vin, eid: Eid, gid: Gid) -> Self {
        Self { vin, eid, gid }
    }
    /// Vehicle Identification Number (17 ASCII characters).
    pub fn vin(&self) -> Vin {
        self.vin
    }
    /// Entity Identifier (6 bytes, typically MAC address).
    pub fn eid(&self) -> Eid {
        self.eid
    }
    /// Group Identifier (6 bytes).
    pub fn gid(&self) -> Gid {
        self.gid
    }
}

impl Default for EcuConfig {
    fn default() -> Self {
        Self {
            vin: defaults::VIN,
            eid: defaults::EID,
            gid: defaults::GID,
        }
    }
}
