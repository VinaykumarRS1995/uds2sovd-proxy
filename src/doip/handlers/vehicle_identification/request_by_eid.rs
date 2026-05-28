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

//! Handler for VehicleIdentificationRequestWithEID (0x0002, ISO 13400-2 §7.6.1.1).

use super::common::create_vi_response;
use crate::doip::{
    PayloadHandler,
    constants::EID_LEN,
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
    types::{Eid, Gid, LogicalAddress, Vin},
};

/// Handles 0x0002 — responds only if the requested EID matches.
pub struct IdentifyVehicleByEidHandler {
    vin: Vin,
    eid: Eid,
    gid: Gid,
    logical_address: LogicalAddress,
}

impl IdentifyVehicleByEidHandler {
    pub fn new(vin: Vin, eid: Eid, gid: Gid, logical_address: LogicalAddress) -> Self {
        Self {
            vin,
            eid,
            gid,
            logical_address,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for IdentifyVehicleByEidHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::VehicleIdentificationRequestWithEid
    }

    fn handle(&self, req: UdpRequest) -> Result<Response, Error> {
        if req.payload().len() != EID_LEN {
            return Err(Error::PayloadTooShort {
                expected: EID_LEN,
                actual: req.payload().len(),
            });
        }
        let requested = Eid::new([
            req.payload()[0],
            req.payload()[1],
            req.payload()[2],
            req.payload()[3],
            req.payload()[4],
            req.payload()[5],
        ]);
        if requested != self.eid {
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

    fn handler() -> IdentifyVehicleByEidHandler {
        IdentifyVehicleByEidHandler::new(TEST_VIN, TEST_EID, TEST_GID, TEST_ADDR)
    }

    #[test]
    fn matching_eid_returns_announcement() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            TEST_EID.as_bytes().to_vec(),
        );
        assert!(handler().handle(req).is_ok());
    }

    #[test]
    fn non_matching_eid_returns_no_match() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            NON_MATCHING_EID.as_bytes().to_vec(),
        );
        assert!(matches!(handler().handle(req), Err(Error::NoMatch)));
    }

    #[test]
    fn wrong_length_returns_error() {
        let req = UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequestWithEid,
            vec![0x00; 3], // 3 bytes — less than required 6
        );
        assert!(matches!(
            handler().handle(req),
            Err(Error::PayloadTooShort {
                expected: 6,
                actual: 3
            })
        ));
    }
}
