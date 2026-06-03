// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP (Diagnostics over IP) protocol implementation per ISO 13400-2.
//!
//! Provides:
//! - Message types and parsing for TCP and UDP transports
//! - Handler trait and dispatcher for routing messages by payload type
//! - Handlers for vehicle identification, routing activation, alive check,
//!   entity status, and diagnostic messages
//! - Protocol constants and type-safe domain types (VIN, EID, LogicalAddress)

pub mod constants;
pub mod dispatch;
pub mod error;
pub mod handlers;
pub mod header;
pub mod message;
pub mod types;

pub use dispatch::{PayloadHandler, TcpDispatcher, UdpDispatcher};
pub use types::{Eid, Gid, LogicalAddress, Vin};

use std::sync::Arc;

// TODO: If the vehicle-identification helper scope grows beyond the current
// small set of factory functions, consider grouping them under a zero-sized
// type for better organization and discoverability.

/// Build the TCP dispatcher with all TCP-legal handlers registered.
///
/// # Parameters
/// logical_addr: This entity's DoIP logical address, used in routing activation
///   and alive check responses.
/// proxy: SOVD backend proxy invoked for every DiagnosticMessage (0x8001).
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
///
/// # Parameters
/// logical_addr: This entity's DoIP logical address included in identification responses.
/// ecu: ECU identity settings (VIN, EID, GID) used in vehicle identification responses.
pub fn udp_dispatcher(
    logical_addr: LogicalAddress,
    ecu: &crate::config::EcuConfig,
) -> UdpDispatcher {
    use handlers::{
        EntityStatusHandler, IdentifyVehicleByEidHandler, IdentifyVehicleByVinHandler,
        IdentifyVehicleHandler,
    };
    let ecu = ecu.clone();
    let mut dispatcher = UdpDispatcher::new();
    dispatcher.register(IdentifyVehicleHandler::new(ecu.clone(), logical_addr));
    dispatcher.register(IdentifyVehicleByEidHandler::new(ecu.clone(), logical_addr));
    dispatcher.register(IdentifyVehicleByVinHandler::new(ecu, logical_addr));
    dispatcher.register(EntityStatusHandler::new(10, 65_535));
    dispatcher
}
