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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::slot::ConnectionSlot;
use crate::doip::message::ConnectionId;

/// Tracks the number of active sessions and enforces the maximum connection limit.
///
/// Uses an atomic counter shared with `ConnectionSlot` — when a slot is dropped
/// (session ends for any reason), the counter decrements automatically. No polling,
/// no background task, no explicit remove() call needed.
pub struct SessionManager {
    max: usize,
    active: Arc<AtomicUsize>,
}

impl SessionManager {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Attempt to acquire a connection slot.
    ///
    /// Returns `Some(ConnectionSlot)` if capacity is available, `None` if the
    /// maximum is already reached. The returned slot auto-decrements the counter
    /// when dropped.
    pub fn try_acquire(&self) -> Option<ConnectionSlot> {
        self.active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < self.max {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .map(|_| {
                let id = ConnectionId::new();
                tracing::debug!(id = %id, active = self.active_count() ,"session slot acquired");
                ConnectionSlot::new(id, Arc::clone(&self.active))
            })
            .map_err(|_| {
                tracing::warn!(max = self.max, "max sessions reached — connection rejected");
            })
            .ok()
    }

    /// Number of sessions currently active.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_increments_active_count() {
        let mgr = SessionManager::new(2);
        assert_eq!(mgr.active_count(), 0);
        let _slot = mgr.try_acquire().unwrap();
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn drop_slot_decrements_active_count() {
        let mgr = SessionManager::new(2);
        let slot = mgr.try_acquire().unwrap();
        assert_eq!(mgr.active_count(), 1);
        drop(slot);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn acquire_fails_at_max_capacity() {
        let mgr = SessionManager::new(1);
        let _slot = mgr.try_acquire().unwrap();
        assert!(mgr.try_acquire().is_none());
    }

    #[test]
    fn acquire_succeeds_after_slot_released() {
        let mgr = SessionManager::new(1);
        let slot = mgr.try_acquire().unwrap();
        drop(slot);
        assert!(mgr.try_acquire().is_some());
    }

    #[test]
    fn zero_max_always_rejects() {
        let mgr = SessionManager::new(0);
        assert!(mgr.try_acquire().is_none());
    }
}
