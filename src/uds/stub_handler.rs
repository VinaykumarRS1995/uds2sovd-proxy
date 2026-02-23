// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! Stub UDS handler for testing utilities

use bytes::Bytes;

use crate::uds::{UdsHandler, UdsRequest, UdsResponse};

/// Stub handler that returns a negative response for all requests.
///
/// The returned NRC (negative response code) is configurable to support
/// different testing scenarios.
#[derive(Debug, Clone)]
pub struct StubHandler {
    nrc: u8,
}

impl StubHandler {
    /// Create a stub handler that always returns the given NRC.
    #[must_use]
    pub fn new(nrc: u8) -> Self {
        Self { nrc }
    }

    /// Create a stub handler that returns NRC 0x11 (Service Not Supported).
    #[must_use]
    pub fn service_not_supported() -> Self {
        Self::new(0x11)
    }
}

impl Default for StubHandler {
    fn default() -> Self {
        Self::service_not_supported()
    }
}

impl UdsHandler for StubHandler {
    fn handle(&self, request: UdsRequest) -> UdsResponse {
        let sid = request.service_id().unwrap_or(0);
        // Negative response: 0x7F + SID + NRC
        let payload = Bytes::from(vec![0x7F, sid, self.nrc]);

        UdsResponse::new(request.target_address, request.source_address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_handler_returns_default_nrc() {
        let handler = StubHandler::default();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from(vec![0x22, 0xF1, 0x90]));

        let response = handler.handle(request);

        assert_eq!(response.payload.as_ref(), &[0x7F, 0x22, 0x11]);
    }

    #[test]
    fn stub_handler_returns_custom_nrc() {
        let handler = StubHandler::new(0x13);
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::new());

        let response = handler.handle(request);

        assert_eq!(response.payload.as_ref(), &[0x7F, 0x00, 0x13]);
    }
}
