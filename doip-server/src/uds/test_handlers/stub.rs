/*
 * Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Stub UDS handler for testing error paths.
//!
//! Always returns a UDS Negative Response Message `[0x7F, SID, NRC]` with a
//! configurable Negative Response Code (NRC). Useful for testing how the
//! `DoIP` server handles ECU-level rejections.
//!
//! Enabled only when the `test-handlers` feature is active (the default).

use bytes::Bytes;

use crate::uds::{UdsHandler, UdsRequest, UdsResponse};

/// UDS Negative Response SID (ISO 14229-1:2020 §8.3) — always `0x7F`.
const NEGATIVE_RESPONSE_SID: u8 = 0x7F;

/// NRC `0x11` — Service Not Supported (ISO 14229-1:2020 Table A.1).
const NRC_SERVICE_NOT_SUPPORTED: u8 = 0x11;

/// Stub handler that returns a UDS Negative Response for all requests.
///
/// The Negative Response Code (NRC) is configurable at construction time.
/// Defaults to `0x11` (Service Not Supported).
///
/// # Example
///
/// ```
/// use doip_server::uds::test_handlers::stub::StubHandler;
/// use doip_server::uds::{UdsHandler, UdsRequest};
/// use bytes::Bytes;
///
/// let handler = StubHandler::default();
/// let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x22, 0xF1, 0x90]));
/// let response = handler.handle(request);
/// assert_eq!(response.payload().as_ref(), &[0x7F, 0x22, 0x11]);
/// ```
#[derive(Debug, Clone)]
pub struct StubHandler {
    /// Negative Response Code returned for every request.
    nrc: u8,
}

impl StubHandler {
    /// Create a stub handler that always returns the given NRC.
    #[must_use]
    pub fn new(nrc: u8) -> Self {
        Self { nrc }
    }

    /// Create a stub handler that returns NRC `0x11` (Service Not Supported).
    #[must_use]
    pub fn service_not_supported() -> Self {
        Self::new(NRC_SERVICE_NOT_SUPPORTED)
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
        // Negative response format per ISO 14229-1: [0x7F, SID, NRC]
        let payload = Bytes::from(vec![NEGATIVE_RESPONSE_SID, sid, self.nrc]);

        UdsResponse::new(request.target_address(), request.source_address(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_nrc_is_service_not_supported() {
        let handler = StubHandler::default();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x22, 0xF1, 0x90]));

        let response = handler.handle(request);

        assert_eq!(response.payload().as_ref(), &[0x7F, 0x22, 0x11]);
        assert_eq!(response.source_address(), 0x1000);
        assert_eq!(response.target_address(), 0x0E00);
    }

    #[test]
    fn custom_nrc_is_returned() {
        let handler = StubHandler::new(0x13); // incorrectMessageLengthOrInvalidFormat
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x10, 0x01]));

        let response = handler.handle(request);

        assert_eq!(response.payload().as_ref(), &[0x7F, 0x10, 0x13]);
    }

    #[test]
    fn empty_payload_uses_sid_zero() {
        let handler = StubHandler::default();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::new());

        let response = handler.handle(request);

        assert_eq!(response.payload().as_ref(), &[0x7F, 0x00, 0x11]);
    }
}
