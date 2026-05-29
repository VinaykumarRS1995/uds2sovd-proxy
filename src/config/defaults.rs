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

use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Default TCP listen address (loopback, standard DoIP port 13400).
pub const TCP_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 13400));

/// Default UDP listen address (all interfaces, standard DoIP port 13400).
pub const UDP_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 13400));

/// Default maximum number of concurrent TCP connections.
pub const MAX_CONNECTIONS: usize = 10;

// TODO: Add DEFAULT_MAX_DATA_SIZE constant for entity status response.

/// Default TCP read buffer size in bytes.
pub const READ_BUFFER_SIZE: usize = 4096;

/// Default DoIP logical address for this server entity.
pub const LOGICAL_ADDRESS: LogicalAddress = LogicalAddress::new(0x0001);

/// Default VIN: 17 ASCII zeroes.
/// Must be overridden with the actual vehicle VIN in production.
pub const VIN: Vin = Vin::new(*b"00000000000000000");

/// Default Entity Identifier: all-zero bytes.
/// Should be set to the MAC address of the DoIP network interface.
pub const EID: Eid = Eid::new([0u8; 6]);

/// Default Group Identifier: all-zero bytes.
pub const GID: Gid = Gid::new([0u8; 6]);
