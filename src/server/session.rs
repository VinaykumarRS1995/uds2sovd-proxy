//! Session management for DoIP connections

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connected,
    RoutingActive,
    Closed,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    pub peer_addr: SocketAddr,
    pub tester_address: u16,
    pub state: SessionState,
}

impl Session {
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        Self {
            id,
            peer_addr,
            tester_address: 0,
            state: SessionState::Connected,
        }
    }

    pub fn activate_routing(&mut self, tester_address: u16) {
        self.tester_address = tester_address;
        self.state = SessionState::RoutingActive;
    }

    pub fn is_routing_active(&self) -> bool {
        self.state == SessionState::RoutingActive
    }
}

#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: RwLock<HashMap<u64, Session>>,
    addr_to_session: RwLock<HashMap<SocketAddr, u64>>,
    next_id: RwLock<u64>,
}

impl SessionManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn create_session(&self, peer_addr: SocketAddr) -> Session {
        let mut next_id = self.next_id.write();
        let id = *next_id;
        *next_id += 1;

        let session = Session::new(id, peer_addr);
        self.sessions.write().insert(id, session.clone());
        self.addr_to_session.write().insert(peer_addr, id);

        session
    }

    pub fn get_session(&self, id: u64) -> Option<Session> {
        self.sessions.read().get(&id).cloned()
    }

    pub fn get_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let id = self.addr_to_session.read().get(addr).copied()?;
        self.get_session(id)
    }

    pub fn update_session<F>(&self, id: u64, f: F) -> bool
    where
        F: FnOnce(&mut Session),
    {
        if let Some(session) = self.sessions.write().get_mut(&id) {
            f(session);
            true
        } else {
            false
        }
    }

    pub fn remove_session(&self, id: u64) -> Option<Session> {
        let session = self.sessions.write().remove(&id)?;
        self.addr_to_session.write().remove(&session.peer_addr);
        Some(session)
    }

    pub fn remove_session_by_addr(&self, addr: &SocketAddr) -> Option<Session> {
        let id = self.addr_to_session.write().remove(addr)?;
        self.sessions.write().remove(&id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_tester_registered(&self, tester_address: u16) -> bool {
        self.sessions
            .read()
            .values()
            .any(|s| s.tester_address == tester_address && s.state == SessionState::RoutingActive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_session() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert_eq!(session.state, SessionState::Connected);

        let retrieved = mgr.get_session(session.id).unwrap();
        assert_eq!(retrieved.peer_addr, addr);
    }

    #[test]
    fn activate_routing() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        mgr.update_session(session.id, |s| s.activate_routing(0x0E80));

        let updated = mgr.get_session(session.id).unwrap();
        assert!(updated.is_routing_active());
        assert_eq!(updated.tester_address, 0x0E80);
    }

    #[test]
    fn remove_session() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert_eq!(mgr.session_count(), 1);

        mgr.remove_session(session.id);
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.get_session(session.id).is_none());
    }

    #[test]
    fn check_tester_registered() {
        let mgr = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let session = mgr.create_session(addr);
        assert!(!mgr.is_tester_registered(0x0E80));

        mgr.update_session(session.id, |s| s.activate_routing(0x0E80));
        assert!(mgr.is_tester_registered(0x0E80));
    }
}
