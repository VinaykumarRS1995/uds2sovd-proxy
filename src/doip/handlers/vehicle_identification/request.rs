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

//! Handler for VehicleIdentificationRequest (0x0001, ISO 13400-2 §7.6.1).

use super::common::create_vi_response;
use crate::doip::{
    PayloadHandler,
    error::Error,
    message::{Response, UdpPayloadType, UdpRequest},
    types::{Eid, Gid, LogicalAddress, Vin},
};

/// Handles 0x0001 — responds to any client unconditionally.
pub struct IdentifyVehicleHandler {
    vin: Vin,
    eid: Eid,
    gid: Gid,
    logical_address: LogicalAddress,
}

impl IdentifyVehicleHandler {
    pub fn new(vin: Vin, eid: Eid, gid: Gid, logical_address: LogicalAddress) -> Self {
        Self {
            vin,
            eid,
            gid,
            logical_address,
        }
    }
}

impl PayloadHandler<UdpPayloadType, UdpRequest> for IdentifyVehicleHandler {
    fn payload_type(&self) -> UdpPayloadType {
        UdpPayloadType::VehicleIdentificationRequest
    }

    fn handle(&self, req: UdpRequest) -> Result<Response, Error> {
        if !req.payload().is_empty() {
            return Err(Error::InvalidPayloadLength {
                declared: req.payload().len() as u32,
                actual: req.payload().len(),
            });
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

    fn handler() -> IdentifyVehicleHandler {
        IdentifyVehicleHandler::new(TEST_VIN, TEST_EID, TEST_GID, TEST_ADDR)
    }

    #[test]
    fn empty_payload_returns_announcement() {
        let resp = handler()
            .handle(UdpRequest::new(
                UdpPayloadType::VehicleIdentificationRequest,
                vec![],
            ))
            .unwrap();
        assert_eq!(
            resp.payload_type(),
            UdpPayloadType::VehicleAnnouncementResponse as u16
        );
        assert_eq!(resp.payload().len(), VI_RESPONSE_LEN);
    }

    #[test]
    fn non_empty_payload_returns_error() {
        let result = handler().handle(UdpRequest::new(
            UdpPayloadType::VehicleIdentificationRequest,
            vec![0x01],
        ));
        assert!(matches!(result, Err(Error::InvalidPayloadLength { .. })));
    }
}
