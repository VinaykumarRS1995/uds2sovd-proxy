//! UDP handler for vehicle discovery

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug};

use crate::doip::{
    DoipHeader, DoipMessage, PayloadType,
    vehicle_id, DOIP_HEADER_LENGTH,
};
use crate::server::ServerConfig;

pub struct UdpHandler {
    config: Arc<ServerConfig>,
}

impl UdpHandler {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    pub async fn run(&self, socket: UdpSocket) {
        info!("UDP handler running on {}", self.config.udp_addr);

        let mut buf = vec![0u8; 1024];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    if len < DOIP_HEADER_LENGTH {
                        continue;
                    }

                    debug!("UDP packet from {}: {} bytes", peer, len);

                    if let Some(response) = self.handle_packet(&buf[..len]) {
                        let response_bytes = response.to_bytes();
                        if let Err(e) = socket.send_to(&response_bytes, peer).await {
                            warn!("Failed to send UDP response to {}: {}", peer, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("UDP receive error: {}", e);
                }
            }
        }
    }

    fn handle_packet(&self, data: &[u8]) -> Option<DoipMessage> {
        let header = DoipHeader::parse(data).ok()?;

        if header.validate().is_some() {
            debug!("Invalid DoIP header received");
            return None;
        }

        let payload_type = PayloadType::from_u16(header.payload_type)?;
        let payload_start = DOIP_HEADER_LENGTH;
        let payload_end = payload_start + header.payload_length as usize;

        if data.len() < payload_end {
            return None;
        }

        let payload = &data[payload_start..payload_end];

        match payload_type {
            PayloadType::VehicleIdentificationRequest => {
                self.handle_vehicle_id_request(payload)
            }
            PayloadType::VehicleIdentificationRequestWithEid => {
                self.handle_vehicle_id_with_eid(payload)
            }
            PayloadType::VehicleIdentificationRequestWithVin => {
                self.handle_vehicle_id_with_vin(payload)
            }
            _ => {
                debug!("Unhandled UDP payload type: {:?}", payload_type);
                None
            }
        }
    }

    fn handle_vehicle_id_request(&self, _payload: &[u8]) -> Option<DoipMessage> {
        info!("Vehicle identification request received");
        Some(self.build_vehicle_id_response())
    }

    fn handle_vehicle_id_with_eid(&self, payload: &[u8]) -> Option<DoipMessage> {
        let request = vehicle_id::RequestWithEid::parse(payload).ok()?;

        // Check if EID matches ours
        if request.eid == self.config.eid {
            info!("Vehicle identification request with matching EID");
            Some(self.build_vehicle_id_response())
        } else {
            debug!("EID mismatch, ignoring request");
            None
        }
    }

    fn handle_vehicle_id_with_vin(&self, payload: &[u8]) -> Option<DoipMessage> {
        let request = vehicle_id::RequestWithVin::parse(payload).ok()?;

        // Check if VIN matches ours
        if request.vin == self.config.vin {
            info!("Vehicle identification request with matching VIN");
            Some(self.build_vehicle_id_response())
        } else {
            debug!("VIN mismatch, ignoring request");
            None
        }
    }

    fn build_vehicle_id_response(&self) -> DoipMessage {
        let response = vehicle_id::Response::new(
            self.config.vin,
            self.config.logical_address,
            self.config.eid,
            self.config.gid,
        ).with_routing_required();

        DoipMessage::new(
            PayloadType::VehicleIdentificationResponse,
            response.to_bytes(),
        )
    }
}
