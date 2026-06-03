// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::collections::HashMap;
use std::hash::Hash;

use crate::doip::error::Error;
use crate::doip::message::{
    HasPayloadType, Response, TcpPayloadType, TcpRequest, UdpPayloadType, UdpRequest,
};

/// Handler for a single payload type on one transport.
///
/// The generic parameters enforce transport segregation at compile time:
/// a `PayloadHandler<TcpPayloadType, TcpRequest>` cannot be registered on
/// a `UdpDispatcher` and vice versa.
pub trait PayloadHandler<PayloadType, Request>: Send + Sync {
    /// The payload type this handler is registered for.
    fn payload_type(&self) -> PayloadType;
    /// Process the request and return a response or error.
    fn handle(&self, req: Request) -> Result<Response, Error>;
}

/// Generic registry and router for payload-type handlers.
///
/// Completely protocol-agnostic. The concrete transport type aliases bind it
/// to specific payload-type enums via [`TcpDispatcher`] and [`UdpDispatcher`].
///
/// # Type safety
///
/// The generic parameters enforce transport segregation at compile time.
/// A handler typed for TCP cannot be registered on a UDP dispatcher and vice
/// versa, preventing an entire class of bugs.
pub struct Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash,
{
    handlers: HashMap<PayloadType, Box<dyn PayloadHandler<PayloadType, Request> + Send + Sync>>,
}

impl<PayloadType, Request> Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash + Into<u16>,
    Request: HasPayloadType<PayloadType>,
{
    /// Create an empty dispatcher with no handlers registered.
    ///
    /// Note: Manual implementation kept for now to avoid proc-macro dependencies.
    /// Future improvement: Consider `#[derive(new)]` if similar patterns emerge across codebase.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for its declared payload type.
    ///
    /// TODO: Consider adding  registration API if handler count grows:
    /// `pub fn register_all(&mut self, handlers: Vec<Box<dyn PayloadHandler<...>>>)`
    pub fn register(&mut self, handler: impl PayloadHandler<PayloadType, Request> + 'static) {
        let payload_type = handler.payload_type();
        self.handlers.insert(payload_type, Box::new(handler));
    }

    /// Route a request to the handler registered for its payload type.
    /// Returns `Err(UnknownPayloadType)` if no handler is registered.
    pub fn dispatch(&self, req: Request) -> Result<Response, Error> {
        let payload_type = req.payload_type();
        self.handlers
            .get(&payload_type)
            .ok_or_else(|| Error::UnknownPayloadType(payload_type.into()))?
            .handle(req)
    }
}

impl<PayloadType, Request> Default for Dispatcher<PayloadType, Request>
where
    PayloadType: Eq + Hash + Into<u16>,
    Request: HasPayloadType<PayloadType>,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatcher bound to the TCP transport payload types.
///
/// # Transport segregation
///
/// The generic type parameters prevent registering a handler for the wrong
/// transport at compile time. For example, a TCP handler cannot be registered
/// on a UDP dispatcher:
///
/// ```compile_fail
/// use uds2sovd::doip::dispatch::UdpDispatcher;
/// use uds2sovd::doip::handlers::AliveCheckHandler;
/// use uds2sovd::doip::types::LogicalAddress;
///
/// let mut dispatcher = UdpDispatcher::new();
/// // AliveCheckHandler implements PayloadHandler<TcpPayloadType, TcpRequest>,
/// // so this will not compile on a UdpDispatcher.
/// dispatcher.register(AliveCheckHandler::new(LogicalAddress::new(0x0001)));
/// ```
pub type TcpDispatcher = Dispatcher<TcpPayloadType, TcpRequest>;

/// Dispatcher bound to the UDP transport payload types.
pub type UdpDispatcher = Dispatcher<UdpPayloadType, UdpRequest>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::error::Error;
    use crate::doip::message::{Response, TcpPayloadType, TcpRequest};

    struct AliveEchoHandler;

    impl PayloadHandler<TcpPayloadType, TcpRequest> for AliveEchoHandler {
        fn payload_type(&self) -> TcpPayloadType {
            TcpPayloadType::AliveCheckRequest
        }
        fn handle(&self, _req: TcpRequest) -> Result<Response, Error> {
            Ok(Response::new(
                TcpPayloadType::AliveCheckResponse as u16,
                vec![],
            ))
        }
    }

    fn make_req(pt: TcpPayloadType) -> TcpRequest {
        TcpRequest::new(pt, vec![])
    }

    #[test]
    fn dispatch_routes_to_registered_handler() {
        let mut dispatcher = TcpDispatcher::new();
        dispatcher.register(AliveEchoHandler);
        let resp = dispatcher
            .dispatch(make_req(TcpPayloadType::AliveCheckRequest))
            .unwrap();
        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::AliveCheckResponse as u16
        );
    }

    #[test]
    fn dispatch_rejects_unknown_type() {
        let dispatcher = TcpDispatcher::new();
        let result = dispatcher.dispatch(make_req(TcpPayloadType::DiagnosticMessage));
        assert!(matches!(result, Err(Error::UnknownPayloadType(0x8001))));
    }
}
