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

//! Handler for VehicleIdentificationRequestWithVIN (0x0003, ISO 13400-2 §7.6.1.2).

use super::common::create_vi_response;
use crate::doip::{
    PayloadHandler,
    constants::VIN_LEN,
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
    types::{Eid, Gid, LogicalAddress, Vin},
};

/// Handles 0x0003 — responds only if the requested VIN matches.
pub struct IdentifyVehicleByVinHandler {
    vin: Vin,
    eid: Eid,
    gid: Gid,
    logical_address: LogicalAddress,
}

impl IdentifyVehicleByVinHandler {
    pub fn new(vin: Vin, eid: Eid, gid: Gid, logical_address: LogicalAddress) -> Self {
        Self {
            vin,
            eid,
            gid,
            logical_address,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for IdentifyVehicleByVinHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::VehicleIdentificationRequestWithVin
    }

    fn handle(&self, req: UdpRequest) -> Result<Response, Error> {
        if req.payload().len() != VIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: VIN_LEN,
                actual: req.payload().len(),
            });
        }
        let mut bytes = [0u8; 17];
        bytes.copy_from_slice(req.payload());
        if Vin::new(bytes) != self.vin {
            return Err(Error::NoMatch);
        }
        Ok(create_vi_response(
            &self.vin,
            &self.eid,
            &self.gid,
            self.logical_address,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::fixtures::*;
    use super::*;

    fn handler() -> IdentifyVehicleByVinHandler {
        IdentifyVehicleByVinHandler::new(TEST_VIN, TEST_EID, TEST_GID, TEST_ADDR)
    }

    #[test]
    fn matching_vin_returns_announcement() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            TEST_VIN.as_bytes().to_vec(),
        );
        assert!(handler().handle(req).is_ok());
    }

    #[test]
    fn non_matching_vin_returns_no_match() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            NON_MATCHING_VIN.as_bytes().to_vec(),
        );
        assert!(matches!(handler().handle(req), Err(Error::NoMatch)));
    }

    #[test]
    fn wrong_length_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithVin,
            vec![0x00; 3], // 3 bytes — less than required 17
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::PayloadTooShort {
                expected: 17,
                actual: 3
            })
        ));
    }
}
