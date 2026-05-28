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

/// DoIP protocol version byte (byte 0 of the generic header), ISO 13400-2 #7.3.
pub const PROTOCOL_VERSION: u8 = 0xFD;

/// Inverse of the protocol version byte (byte 1 of the generic header).
/// Must equal `!PROTOCOL_VERSION` for the header to be considered valid.
pub const INVERSE_VERSION: u8 = 0x02; // !0xFD

/// Size of the DoIP generic header in bytes (ISO 13400-2 #7.3).
pub const HEADER_LEN: usize = 8;

// RoutingActivation response codes (ISO 13400-2 #9.9, Table 28)

/// Routing activation successful.
pub const ROUTING_ACTIVATION_CODE_SUCCESS: u8 = 0x10;

// DiagnosticMessage ACK codes (ISO 13400-2 #9.11, Table 33)

/// Diagnostic message received and forwarded to the target network.
pub const DIAGNOSTIC_MESSAGE_ACK: u8 = 0x00;

// VehicleIdentification / VehicleAnnouncement (ISO 13400-2 #7.6.2)

/// No further action is required from the client.
pub const NO_FURTHER_ACTION: u8 = 0x00;

// Generic DoIP header NACK codes (ISO 13400-2 §9.4, Table 18)

/// Header fields do not match the expected pattern (bad version or inverse byte).
pub const NACK_INCORRECT_PATTERN: u8 = 0x00;

/// Payload type is not supported by this entity.
pub const NACK_UNKNOWN_PAYLOAD_TYPE: u8 = 0x01;

/// Message is too large to be processed.
pub const NACK_MESSAGE_TOO_LARGE: u8 = 0x02;

/// Server ran out of memory.
pub const NACK_OUT_OF_MEMORY: u8 = 0x03;

/// Payload length field does not match actual payload size.
pub const NACK_INVALID_PAYLOAD_LENGTH: u8 = 0x04;

/// Receive buffer size for UDP DoIP datagrams.
/// All ISO 13400-2 defined UDP messages fit within a single Ethernet frame (MTU 1500 bytes).
/// The largest defined message is VehicleAnnouncementResponse at 40 bytes.
pub const UDP_RECV_BUF_SIZE: usize = 1500;

/// Field lengths (ISO 13400-2)
/// VIN (Vehicle Identification Number) length in bytes.
pub const VIN_LEN: usize = 17;

/// EID (Entity Identification / MAC address) length in bytes.
pub const EID_LEN: usize = 6;

//   Entity status (ISO 13400-2 §7.6.3)

/// DoIP node type: DoIP gateway (0x00) or DoIP node (0x01).
pub const DOIP_NODE_TYPE: u8 = 0x01;

/// Entity status response payload length: 1 (node type) + 1 (max TCP) + 1 (current TCP) + 4 (max data size).
pub const ENTITY_STATUS_RESPONSE_LEN: usize = 7;

//   Maximum payload (ISO 13400-2 §7.3)

/// Maximum DoIP payload length accepted by this implementation.
pub const MAX_DOIP_PAYLOAD_LEN: usize = 65_535;

//   Routing Activation (ISO 13400-2 §9.9)

/// Minimum length of a routing activation request payload (bytes).
pub const ROUTING_ACTIVATION_REQUEST_MIN_LEN: usize = 11;

//   Diagnostic Message (ISO 13400-2 §9.11)

/// Minimum diagnostic message payload length: 2 (source addr) + 2 (target addr).
pub const DIAG_MSG_MIN_PAYLOAD_LEN: usize = 4;

/// Diagnostic message positive ACK header length: 2 (source) + 2 (target) + 1 (ACK code).
pub const DIAG_ACK_HEADER_LEN: usize = 5;

//   UDS response codes (ISO 14229-1)

/// UDS negative response service ID.
pub const UDS_NEGATIVE_RESPONSE: u8 = 0x7F;

/// UDS NRC: service not supported.
pub const NRC_SERVICE_NOT_SUPPORTED: u8 = 0x11;
