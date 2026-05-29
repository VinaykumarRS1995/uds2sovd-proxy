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

use serde::Deserialize;

/// DoIP logical address (2-byte big-endian value, ISO 13400-2 #7.3).
/// Identifies a DoIP entity (ECU or DoIP gateway) within the vehicle network.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct LogicalAddress(u16);

impl LogicalAddress {
    /// Create a new logical address from a raw `u16`.
    pub const fn new(addr: u16) -> Self {
        Self(addr)
    }
    /// Serialise as big-endian bytes for on-wire use.
    pub fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl From<u16> for LogicalAddress {
    fn from(addr: u16) -> Self {
        Self(addr)
    }
}

/// Vehicle Identification Number (ISO 3779): 17 ASCII bytes.
/// In TOML, specify as an array of byte values (e.g., `vin = [48, 48, ...]`).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct Vin([u8; 17]);

impl Vin {
    /// Create a VIN from a 17-byte array.
    pub const fn new(bytes: [u8; 17]) -> Self {
        Self(bytes)
    }
    /// Raw bytes for on-wire serialisation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Entity Identifier: 6 bytes, typically the MAC address of the DoIP node's
/// network interface (ISO 13400-2 #7.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct Eid([u8; 6]);

impl Eid {
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Group Identifier: 6 bytes, used to group DoIP entities that share a subnet
/// (ISO 13400-2 #7.6.2).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Gid([u8; 6]);

impl Gid {
    /// Create a GID from a 6-byte array.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
    /// Raw bytes for on-wire serialisation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
