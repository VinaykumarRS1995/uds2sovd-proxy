use crate::doip::{
    PayloadHandler,
    constants::{ROUTING_ACTIVATION_CODE_SUCCESS, ROUTING_ACTIVATION_REQUEST_MIN_LEN},
    error::Error,
    message::{Response, TcpPayloadType, TcpRequest},
    types::LogicalAddress,
};

/// Handles RoutingActivationRequest (0x0005, ISO 13400-2 §9.9).
/// Currently always returns success (0x10); state machine is future work.
pub struct RoutingActivationHandler {
    server_logical_address: LogicalAddress,
}

impl RoutingActivationHandler {
    pub fn new(server_logical_address: LogicalAddress) -> Self {
        Self {
            server_logical_address,
        }
    }

    /// Shared protocol logic (ISO 13400-2 #9.9).
    /// Returns a RoutingActivationResponse payload.
    fn activate(&self, client_address: u16, _activation_type: u8) -> Response {
        // Payload layout (13 bytes):
        //   [0..2]  client logical address
        //   [2..4]  server logical address
        //   [4]     response code: 0x10 = success
        //   [5..9]  reserved ISO (0x00000000)
        //   [9..13] reserved OEM (0x00000000)
        let mut payload = Vec::with_capacity(13);
        payload.extend_from_slice(&client_address.to_be_bytes());
        payload.extend_from_slice(&self.server_logical_address.to_be_bytes());
        payload.push(ROUTING_ACTIVATION_CODE_SUCCESS);
        payload.extend_from_slice(&[0u8; 4]); // reserved ISO
        payload.extend_from_slice(&[0u8; 4]); // reserved OEM
        Response::new(TcpPayloadType::RoutingActivationResponse as u16, payload)
    }
}

impl PayloadHandler<TcpPayloadType, TcpRequest> for RoutingActivationHandler {
    fn payload_type(&self) -> TcpPayloadType {
        TcpPayloadType::RoutingActivationRequest
    }

    fn handle(&self, req: TcpRequest) -> Result<Response, Error> {
        // Payload layout (11 bytes): source_addr(2) + activation_type(1) + reserved(8)
        if req.payload().len() < ROUTING_ACTIVATION_REQUEST_MIN_LEN {
            return Err(Error::PayloadTooShort {
                expected: ROUTING_ACTIVATION_REQUEST_MIN_LEN,
                actual: req.payload().len(),
            });
        }
        let client_address = u16::from_be_bytes([req.payload()[0], req.payload()[1]]);
        let activation_type = req.payload()[2];
        Ok(self.activate(client_address, activation_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doip::types::LogicalAddress;

    fn make_req(payload: Vec<u8>) -> TcpRequest {
        TcpRequest::new(TcpPayloadType::RoutingActivationRequest, payload)
    }

    #[test]
    fn handle_valid_request_returns_activation_success() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        let resp = handler
            .handle(make_req(vec![0x00, 0x42, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(
            resp.payload_type(),
            TcpPayloadType::RoutingActivationResponse as u16
        );
        assert_eq!(
            resp.payload()[4], 0x10,
            "response code must be 0x10 (success)"
        );
        // client address echoed back
        assert_eq!(&resp.payload()[0..2], &[0x00, 0x42]);
        // server address
        assert_eq!(&resp.payload()[2..4], &[0x00, 0x01]);
    }

    #[test]
    fn handle_rejects_short_payload() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        assert!(matches!(
            handler.handle(make_req(vec![0x00])),
            Err(Error::PayloadTooShort { .. })
        ));
    }

    #[test]
    fn handle_rejects_partial_payload() {
        let handler = RoutingActivationHandler::new(LogicalAddress::new(0x0001));
        assert!(matches!(
            handler.handle(make_req(vec![0x00, 0x42, 0x00])),
            Err(Error::PayloadTooShort {
                expected: 11,
                actual: 3
            })
        ));
    }
}
