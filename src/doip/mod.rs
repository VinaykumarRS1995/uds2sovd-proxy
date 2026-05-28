// Copyright (c) 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

pub mod constants;
pub mod dispatch;
pub mod error;
pub mod handlers;
pub mod message;
pub mod types;

pub use dispatch::{PayloadHandler, TcpDispatcher, UdpDispatcher};
pub use types::{Eid, Gid, LogicalAddress, Vin};

use std::sync::Arc;

/// Build the TCP dispatcher with all TCP-legal handlers registered.
/// `proxy` is called for every DiagnosticMessage (0x8001).
pub fn tcp_dispatcher(
    logical_addr: LogicalAddress,
    proxy: Arc<dyn crate::proxy::SovdProxy>,
) -> TcpDispatcher {
    use handlers::{AliveCheckHandler, DiagnosticsHandler, RoutingActivationHandler};
    let mut dispatcher = TcpDispatcher::new();
    dispatcher.register(RoutingActivationHandler::new(logical_addr));
    dispatcher.register(AliveCheckHandler::new(logical_addr));
    dispatcher.register(DiagnosticsHandler::new(proxy));
    dispatcher
}

/// Build the UDP dispatcher with all UDP-legal handlers registered.
pub fn udp_dispatcher(logical_addr: LogicalAddress, vin: Vin, eid: Eid, gid: Gid) -> UdpDispatcher {
    use handlers::{
        EntityStatusHandler, IdentifyVehicleByEidHandler, IdentifyVehicleByVinHandler,
        IdentifyVehicleHandler,
    };
    let mut dispatcher = UdpDispatcher::new();
    dispatcher.register(IdentifyVehicleHandler::new(vin, eid, gid, logical_addr));
    dispatcher.register(IdentifyVehicleByEidHandler::new(
        vin,
        eid,
        gid,
        logical_addr,
    ));
    dispatcher.register(IdentifyVehicleByVinHandler::new(
        vin,
        eid,
        gid,
        logical_addr,
    ));
    dispatcher.register(EntityStatusHandler::new(10, 65_535));
    dispatcher
}
