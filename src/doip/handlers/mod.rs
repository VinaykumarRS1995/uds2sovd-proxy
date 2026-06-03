// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Payload handlers — one per DoIP message type.

pub mod alive_check;
pub mod diagnostics;
pub mod entity_status;
pub mod routing_activation;
pub mod vehicle_identification;

pub use alive_check::AliveCheckHandler;
pub use diagnostics::DiagnosticsHandler;
pub use entity_status::EntityStatusHandler;
pub use routing_activation::RoutingActivationHandler;
pub use vehicle_identification::{
    IdentifyVehicleByEidHandler, IdentifyVehicleByVinHandler, IdentifyVehicleHandler,
};
