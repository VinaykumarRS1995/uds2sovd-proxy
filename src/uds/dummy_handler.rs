// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! Dummy ECU handler for integration testing

use bytes::Bytes;
use tracing::{debug, info};

use crate::uds::{UdsHandler, UdsRequest, UdsResponse};

/// Dummy ECU Handler - Returns positive responses for `DoIP` Transmitter integration testing
///
/// This handler returns a simple positive response (SID + 0x40) for any diagnostic request.
/// Used for integration testing with external `DoIP` Transmitters.
#[derive(Debug, Clone, Default)]
pub struct DummyEcuHandler;

impl DummyEcuHandler {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build positive response: SID + 0x40 followed by response data
    fn positive_response(sid: u8, data: &[u8]) -> Bytes {
        let mut resp = vec![sid.saturating_add(0x40)];
        resp.extend_from_slice(data);
        Bytes::from(resp)
    }
}

impl UdsHandler for DummyEcuHandler {
    fn handle(&self, request: UdsRequest) -> UdsResponse {
        let sid = request.service_id().unwrap_or(0);

        info!(
            "UDS Request: SA=0x{:04X} TA=0x{:04X} SID=0x{:02X} len={}",
            request.source_address,
            request.target_address,
            sid,
            request.payload.len()
        );
        debug!("UDS Data: {:02X?}", request.payload.as_ref());

        // Simple positive response: SID + 0x40 (positive response SID)
        // Echo back the sub-function byte if present
        let response_data = if let Some(&sub_fn) = request.payload.get(1) {
            // Include sub-function byte in response
            Self::positive_response(sid, &[sub_fn])
        } else {
            // Just the positive response SID
            Self::positive_response(sid, &[])
        };

        info!("UDS Positive Response: {:02X?}", response_data.as_ref());

        UdsResponse::new(
            request.target_address,
            request.source_address,
            response_data,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_ecu_handler_positive_response_with_subfunction() {
        let handler = DummyEcuHandler::new();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from(vec![0x10, 0x02]));

        let response = handler.handle(request);

        assert_eq!(response.payload.as_ref(), &[0x50, 0x02]);
        assert_eq!(response.source_address, 0x1000);
        assert_eq!(response.target_address, 0x0E00);
    }

    #[test]
    fn dummy_ecu_handler_positive_response_without_subfunction() {
        let handler = DummyEcuHandler::new();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from(vec![0x3E]));

        let response = handler.handle(request);

        assert_eq!(response.payload.as_ref(), &[0x7E]);
    }
}
