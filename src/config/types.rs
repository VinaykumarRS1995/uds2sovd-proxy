// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Configuration data model
//!
//! This module defines the runtime configuration used by the DoIP server.
//!
//! Configuration is grouped into TCP, UDP, and ECU sections.
//!
//! Configuration values are deserialized from TOML files via serde and may fall back to compile-time defaults if not specified.
use serde::Deserialize;
use std::net::SocketAddr;

use super::defaults;
use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};

/// Top-level server configuration, split into TCP, UDP, and ECU sections.
///
/// Private fields
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
    /// Consumes the configuration and returns the individual
    /// transport and ECU configuration sections.
    ///
    /// This encourages explicit ownership transfer and makes
    /// configuration usage visible at the call site.
    pub fn into_parts(self) -> (TcpConfig, UdpConfig, EcuConfig) {
        (self.tcp, self.udp, self.ecu)
    }
}

/// TCP transport configuration.
///
/// Controls how the DoIP server accepts and manages
/// TCP diagnostic connections.
///
/// `#[serde(default)]` allows partial TOML files.
/// Missing fields fall back to compile-time defaults.

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

/// UDP transport configuration.
///
/// Controls DoIP vehicle discovery and stateless UDP communication.
///
/// `#[serde(default)]` allows partial TOML files.
/// Missing fields fall back to compile-time defaults.
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

/// ECU identity information advertised by the DoIP entity.
///
/// These values are included in vehicle identification
/// and entity status responses defined by ISO 13400-2.
///
/// Note: No `#[serde(default)]` is used because ECU identity
/// values should be explicitly configured.
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
    /// Returns the configured Vehicle Identification Number (VIN).
    ///
    /// VIN is a 17-character vehicle identifier defined by ISO 3779.    
    pub fn vin(&self) -> Vin {
        self.vin
    }
    /// Entity Identifier (6 bytes, typically MAC address).
    pub fn eid(&self) -> Eid {
        self.eid
    }
    /// Returns the configured Group Identifier (GID).
    ///
    /// GID identifies a logical group of DoIP entities.
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
