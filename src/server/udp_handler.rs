//! UDP handler for vehicle discovery

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::doip::{vehicle_id, DoipHeader, DoipMessage, PayloadType, DOIP_HEADER_LENGTH};
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
                        debug!("UDP packet too short from {}: {} bytes", peer, len);
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

        // Store incoming version to mirror in response
        let version = header.version;

        let payload_type = PayloadType::from_u16(header.payload_type)?;
        let payload_start = DOIP_HEADER_LENGTH;
        let payload_end = payload_start + header.payload_length as usize;

        if data.len() < payload_end {
            return None;
        }

        let payload = &data[payload_start..payload_end];

        match payload_type {
            PayloadType::VehicleIdentificationRequest => {
                self.handle_vehicle_id_request(payload, version)
            }
            PayloadType::VehicleIdentificationRequestWithEid => {
                self.handle_vehicle_id_with_eid(payload, version)
            }
            PayloadType::VehicleIdentificationRequestWithVin => {
                self.handle_vehicle_id_with_vin(payload, version)
            }
            _ => {
                debug!("Unhandled UDP payload type: {:?}", payload_type);
                None
            }
        }
    }

    fn handle_vehicle_id_request(&self, _payload: &[u8], version: u8) -> Option<DoipMessage> {
        info!("Vehicle identification request received");
        Some(self.build_vehicle_id_response(version))
    }

    fn handle_vehicle_id_with_eid(&self, payload: &[u8], version: u8) -> Option<DoipMessage> {
        let request = vehicle_id::RequestWithEid::parse(payload).ok()?;

        // Check if EID matches ours
        if request.eid == self.config.eid {
            Some(self.build_vehicle_id_response(version))
        } else {
            debug!("EID mismatch, ignoring request");
            None
        }
    }

    fn handle_vehicle_id_with_vin(&self, payload: &[u8], version: u8) -> Option<DoipMessage> {
        let request = vehicle_id::RequestWithVin::parse(payload).ok()?;

        // Check if VIN matches ours
        if request.vin == self.config.vin {
            Some(self.build_vehicle_id_response(version))
        } else {
            debug!("VIN mismatch, ignoring request");
            None
        }
    }

    fn build_vehicle_id_response(&self, version: u8) -> DoipMessage {
        let response = vehicle_id::Response::new(
            self.config.vin,
            self.config.logical_address,
            self.config.eid,
            self.config.gid,
        )
        .with_routing_required();

        // Mirror the protocol version from the request
        DoipMessage::with_version(
            version,
            PayloadType::VehicleIdentificationResponse,
            response.to_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::{vehicle_id, DoipMessage, PayloadType};
    use crate::server::ServerConfig;
    use bytes::Bytes;

    fn build_packet(version: u8, payload_type: PayloadType, payload: Bytes) -> Bytes {
        DoipMessage::with_version(version, payload_type, payload).to_bytes()
    }

    fn handler_with_config(config: ServerConfig) -> UdpHandler {
        UdpHandler::new(Arc::new(config))
    }

    #[test]
    fn vehicle_id_request_returns_response_with_same_version() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config.clone());
        let version = 0x03;

        let packet = build_packet(
            version,
            PayloadType::VehicleIdentificationRequest,
            Bytes::new(),
        );
        let response = handler.handle_packet(&packet).expect("expected response");

        assert_eq!(response.header.version, version);
        assert_eq!(
            response.payload_type(),
            Some(PayloadType::VehicleIdentificationResponse)
        );

        let parsed =
            vehicle_id::Response::parse(&response.payload).expect("valid response payload");
        assert_eq!(parsed.vin, config.vin);
        assert_eq!(parsed.logical_address, config.logical_address);
        assert_eq!(parsed.eid, config.eid);
        assert_eq!(parsed.gid, config.gid);
        assert_eq!(
            parsed.further_action,
            vehicle_id::FurtherAction::RoutingActivationRequired
        );
    }

    #[test]
    fn vehicle_id_with_eid_match_returns_response() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config.clone());

        let payload = Bytes::copy_from_slice(&config.eid);
        let packet = build_packet(
            0x02,
            PayloadType::VehicleIdentificationRequestWithEid,
            payload,
        );
        let response = handler.handle_packet(&packet);

        assert!(response.is_some());
    }

    #[test]
    fn vehicle_id_with_eid_mismatch_returns_none() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config);

        let payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let packet = build_packet(
            0x02,
            PayloadType::VehicleIdentificationRequestWithEid,
            payload,
        );
        let response = handler.handle_packet(&packet);

        assert!(response.is_none());
    }

    #[test]
    fn vehicle_id_with_vin_match_returns_response() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config.clone());

        let payload = Bytes::copy_from_slice(&config.vin);
        let packet = build_packet(
            0x02,
            PayloadType::VehicleIdentificationRequestWithVin,
            payload,
        );
        let response = handler.handle_packet(&packet);

        assert!(response.is_some());
    }

    #[test]
    fn vehicle_id_with_vin_mismatch_returns_none() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config);

        let payload = Bytes::copy_from_slice(b"WVWZZZ3CZWE123456");
        let packet = build_packet(
            0x02,
            PayloadType::VehicleIdentificationRequestWithVin,
            payload,
        );
        let response = handler.handle_packet(&packet);

        assert!(response.is_none());
    }

    #[test]
    fn short_packet_returns_none() {
        let config = ServerConfig::default();
        let handler = handler_with_config(config);

        let response = handler.handle_packet(&[0x02, 0xFD]);
        assert!(response.is_none());
    }
}
