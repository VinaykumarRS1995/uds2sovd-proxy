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

//! Vehicle Identification handlers (ISO 13400-2 §7.6).

mod common;
mod request;
mod request_by_eid;
mod request_by_vin;

pub use request::IdentifyVehicleHandler;
pub use request_by_eid::IdentifyVehicleByEidHandler;
pub use request_by_vin::IdentifyVehicleByVinHandler;
