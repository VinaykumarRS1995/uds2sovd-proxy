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

//! Shared response builder for Vehicle Identification handlers (ISO 13400-2 §7.6.2).

use crate::doip::{
    constants::NO_FURTHER_ACTION,
    message::{Response, UdpPayloadType},
    types::{Eid, Gid, LogicalAddress, Vin},
};

/// 17 (VIN) + 2 (addr) + 6 (EID) + 6 (GID) + 1 (action byte) = 32
pub(super) const VI_RESPONSE_LEN: usize = 32;

/// Builds the 32-byte Vehicle Identification Response / Announcement payload.
///
/// Layout:
/// ```text
/// [0..17]  VIN
/// [17..19] logical address (big-endian)
/// [19..25] EID
/// [25..31] GID
/// [31]     further action required (0x00 = none)
/// ```
pub(super) fn create_vi_response(
    vin: &Vin,
    eid: &Eid,
    gid: &Gid,
    logical_address: LogicalAddress,
) -> Response {
    let mut payload = Vec::with_capacity(VI_RESPONSE_LEN);
    payload.extend_from_slice(vin.as_bytes());
    payload.extend_from_slice(&logical_address.to_be_bytes());
    payload.extend_from_slice(eid.as_bytes());
    payload.extend_from_slice(gid.as_bytes());
    payload.push(NO_FURTHER_ACTION);
    Response::new(UdpPayloadType::VehicleAnnouncementResponse as u16, payload)
}

#[cfg(test)]
pub(super) mod fixtures {
    use crate::doip::types::{Eid, Gid, LogicalAddress, Vin};

    /// ISO example VIN (17 ASCII characters, valid format)
    pub const TEST_VIN: Vin = Vin::new(*b"1HGBH41JXMN109186");

    // Sample MAC address used as EID (6 bytes)
    pub const TEST_EID: Eid = Eid::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);

    /// Group ID (6 bytes, all-zero = no grouping per ISO 13400-2)
    pub const TEST_GID: Gid = Gid::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    /// ECU logical address (ISO 13400-2 range 0x0001–0x0DFF)
    pub const TEST_ADDR: LogicalAddress = LogicalAddress::new(0x0E01);

    /// EID that does NOT match TEST_EID (broadcast address, clearly different)
    pub const NON_MATCHING_EID: Eid = Eid::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    /// VIN that does NOT match TEST_VIN (valid format, different vehicle)
    pub const NON_MATCHING_VIN: Vin = Vin::new(*b"WVWZZZ3CZWE123456");

    /// Expected response payload length
    pub const VI_RESPONSE_LEN: usize = super::VI_RESPONSE_LEN;
}
