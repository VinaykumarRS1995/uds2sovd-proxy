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

use crate::doip::error::Error;

/// Top-level application error.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Doip(#[from] Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
