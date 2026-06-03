// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! Vehicle Identification handlers (ISO 13400-2 §7.6).
//!
//! Split into one module per request variant (0x0001, 0x0002, 0x0003)
//! with shared response assembly in utils. Each handler implements
//! "PayloadHandler<UdpPayloadType, UdpRequest>".
//!
mod request;
mod request_by_eid;
mod request_by_vin;
mod utils;

pub use request::IdentifyVehicleHandler;
pub use request_by_eid::IdentifyVehicleByEidHandler;
pub use request_by_vin::IdentifyVehicleByVinHandler;
