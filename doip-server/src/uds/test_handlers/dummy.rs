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

//! Dummy ECU handler for integration testing and demos.
//!
//! Returns a positive UDS response `(SID + 0x40)` for every incoming request.
//! Suitable for verifying end-to-end `DoIP` connectivity without a real ECU.
//!
//! Enabled only when the `test-handlers` feature is active (the default).
//! Production deployments should replace this with a real [`UdsHandler`] implementation.

use bytes::Bytes;
use tracing::{debug, info};

use crate::uds::{UdsHandler, UdsRequest, UdsResponse};

/// UDS positive response offset added to the request SID (ISO 14229-1:2020 §8.3).
const POSITIVE_RESPONSE_SID_OFFSET: u8 = 0x40;

/// Dummy ECU handler — returns a positive UDS response for any diagnostic request.
///
/// The positive response SID is computed as `request_sid + 0x40` per ISO 14229-1:2020.
/// If the request contains a sub-function byte, it is echoed back in the response.
///
/// # Example
///
/// ```no_run
/// use doip_server::uds::test_handlers::dummy::DummyEcuHandler;
/// use doip_server::uds::{UdsHandler, UdsRequest};
/// use bytes::Bytes;
///
/// # async fn run() {
/// let handler = DummyEcuHandler::new();
/// let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x10, 0x02]));
/// let response = handler.handle(request).await.unwrap();
/// assert_eq!(response.payload().as_ref(), &[0x50, 0x02]);
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct DummyEcuHandler;

impl DummyEcuHandler {
    /// Create a new `DummyEcuHandler`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build a positive UDS response: `[SID + 0x40, sub_fn?]`.
    fn positive_response(sid: u8, data: &[u8]) -> Bytes {
        let mut resp = vec![sid.saturating_add(POSITIVE_RESPONSE_SID_OFFSET)];
        resp.extend_from_slice(data);
        Bytes::from(resp)
    }
}

impl UdsHandler for DummyEcuHandler {
    fn handle(
        &self,
        request: UdsRequest,
    ) -> impl std::future::Future<Output = crate::Result<UdsResponse>> + Send {
        let sid = request.service_id().unwrap_or(0);

        info!(
            sa = format!("0x{:04X}", request.source_address()),
            ta = format!("0x{:04X}", request.target_address()),
            sid = format!("0x{:02X}", sid),
            len = request.payload().len(),
            "UDS request received"
        );
        debug!(
            data = format!("{:02X?}", request.payload().as_ref()),
            "UDS payload"
        );

        // Echo sub-function byte if present (payload byte index 1)
        let response_data = if let Some(&sub_fn) = request.payload().get(1) {
            Self::positive_response(sid, &[sub_fn])
        } else {
            Self::positive_response(sid, &[])
        };

        info!(
            response = format!("{:02X?}", response_data.as_ref()),
            "UDS positive response"
        );

        let resp = UdsResponse::new(
            request.target_address(),
            request.source_address(),
            response_data,
        );
        std::future::ready(Ok(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn positive_response_with_sub_function() {
        let handler = DummyEcuHandler::new();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x10, 0x02]));

        let response = handler.handle(request).await.unwrap();

        // 0x10 + 0x40 = 0x50, sub-function 0x02 echoed
        assert_eq!(response.payload().as_ref(), &[0x50, 0x02]);
        assert_eq!(response.source_address(), 0x1000);
        assert_eq!(response.target_address(), 0x0E00);
    }

    #[tokio::test]
    async fn positive_response_without_sub_function() {
        let handler = DummyEcuHandler::new();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::from_static(&[0x3E]));

        let response = handler.handle(request).await.unwrap();

        // 0x3E + 0x40 = 0x7E, no sub-function
        assert_eq!(response.payload().as_ref(), &[0x7E]);
        assert_eq!(response.source_address(), 0x1000);
        assert_eq!(response.target_address(), 0x0E00);
    }

    #[tokio::test]
    async fn empty_payload_returns_response_sid_zero() {
        let handler = DummyEcuHandler::new();
        let request = UdsRequest::new(0x0E00, 0x1000, Bytes::new());

        let response = handler.handle(request).await.unwrap();

        // SID = 0, 0x00 + 0x40 = 0x40
        assert_eq!(response.payload().as_ref(), &[0x40]);
    }
}
