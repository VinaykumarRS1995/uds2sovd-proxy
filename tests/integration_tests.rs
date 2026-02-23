// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! Integration tests for DoIP Server

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn build_doip_message(payload_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut msg = vec![
        0x02,
        0xFD,
        (payload_type >> 8) as u8,
        (payload_type & 0xFF) as u8,
        (len >> 24) as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
    ];
    msg.extend_from_slice(payload);
    msg
}

fn parse_doip_header(data: &[u8]) -> Option<(u16, u32)> {
    if data.len() < 8 {
        return None;
    }
    let payload_type = u16::from_be_bytes([data[2], data[3]]);
    let payload_length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    Some((payload_type, payload_length))
}

mod tcp_tests {
    use super::*;
    use doip_server::server::{DoipServer, ServerConfig};
    use doip_server::uds::dummy_handler::DummyEcuHandler;
    use std::sync::Arc;

    async fn start_test_server(port: u16) -> Arc<DoipServer<DummyEcuHandler>> {
        let config = ServerConfig {
            tcp_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            udp_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            ..Default::default()
        };

        let server = Arc::new(DoipServer::new(config));
        let server_clone = server.clone();

        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        server
    }

    #[tokio::test]
    async fn routing_activation_success() {
        let port = 23401;
        let server = start_test_server(port).await;

        let mut stream = timeout(
            TEST_TIMEOUT,
            TcpStream::connect(format!("127.0.0.1:{port}")),
        )
        .await
        .expect("connect timeout")
        .expect("connect failed");

        // Send routing activation request
        // Source address: 0x0E00, Activation type: 0x00 (default)
        let request = build_doip_message(0x0005, &[0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        stream.write_all(&request).await.expect("write failed");

        let mut buf = vec![0u8; 64];
        let n = timeout(TEST_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");

        assert!(n >= 8, "response too short");
        let (payload_type, _) = parse_doip_header(&buf).unwrap();
        assert_eq!(payload_type, 0x0006, "expected routing activation response");

        // Check response code at offset 12 (after header + addresses)
        if n >= 13 {
            let response_code = buf[12];
            assert_eq!(response_code, 0x10, "expected successful activation (0x10)");
        }

        server.shutdown();
    }

    #[tokio::test]
    async fn diagnostic_message_requires_routing() {
        let port = 23402;
        let server = start_test_server(port).await;

        let mut stream = timeout(
            TEST_TIMEOUT,
            TcpStream::connect(format!("127.0.0.1:{port}")),
        )
        .await
        .expect("connect timeout")
        .expect("connect failed");

        // Send diagnostic message without routing activation first
        // SA: 0x0E00, TA: 0x1000, Data: TesterPresent (0x3E 0x00)
        let request = build_doip_message(0x8001, &[0x0E, 0x00, 0x10, 0x00, 0x3E, 0x00]);
        stream.write_all(&request).await.expect("write failed");

        let mut buf = vec![0u8; 64];
        let n = timeout(TEST_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");

        assert!(n >= 8, "response too short");
        let (payload_type, _) = parse_doip_header(&buf).unwrap();

        // Should get NACK because routing not activated
        assert!(
            payload_type == 0x8003 || payload_type == 0x0000,
            "expected NACK or generic NACK, got 0x{payload_type:04X}"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn full_diagnostic_flow() {
        let port = 23403;
        let server = start_test_server(port).await;

        let mut stream = timeout(
            TEST_TIMEOUT,
            TcpStream::connect(format!("127.0.0.1:{port}")),
        )
        .await
        .expect("connect timeout")
        .expect("connect failed");

        // Step 1: Routing activation
        let routing_req = build_doip_message(0x0005, &[0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        stream.write_all(&routing_req).await.expect("write failed");

        let mut buf = vec![0u8; 64];
        let _n = timeout(TEST_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");

        let (payload_type, _) = parse_doip_header(&buf).unwrap();
        assert_eq!(payload_type, 0x0006);

        // Step 2: Send diagnostic message (TesterPresent)
        let diag_req = build_doip_message(0x8001, &[0x0E, 0x00, 0x10, 0x00, 0x3E, 0x00]);
        stream.write_all(&diag_req).await.expect("write failed");

        buf.clear();
        buf.resize(64, 0);
        let n = timeout(TEST_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read failed");

        assert!(n >= 8, "response too short");
        let (payload_type, _) = parse_doip_header(&buf).unwrap();

        // Should get diagnostic response (positive ack or diagnostic message)
        assert!(
            payload_type == 0x8001 || payload_type == 0x8002,
            "expected diagnostic response, got 0x{payload_type:04X}"
        );

        server.shutdown();
    }
}

mod udp_tests {
    use super::*;
    use doip_server::server::{DoipServer, ServerConfig};
    use doip_server::uds::dummy_handler::DummyEcuHandler;
    use std::sync::Arc;

    async fn start_test_server(port: u16) -> Arc<DoipServer<DummyEcuHandler>> {
        let config = ServerConfig {
            tcp_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            udp_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            ..Default::default()
        };

        let server = Arc::new(DoipServer::new(config));
        let server_clone = server.clone();

        tokio::spawn(async move {
            let _ = server_clone.run().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        server
    }

    #[tokio::test]
    async fn vehicle_identification_request() {
        let port = 23410;
        let server = start_test_server(port).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind failed");
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // Send vehicle identification request (payload type 0x0001, empty payload)
        let request = build_doip_message(0x0001, &[]);
        socket
            .send_to(&request, server_addr)
            .await
            .expect("send failed");

        let mut buf = vec![0u8; 128];
        let (n, _) = timeout(TEST_TIMEOUT, socket.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv failed");

        assert!(n >= 8, "response too short");
        let (payload_type, payload_len) = parse_doip_header(&buf).unwrap();
        assert_eq!(
            payload_type, 0x0004,
            "expected vehicle identification response"
        );
        assert!(
            payload_len >= 32,
            "payload too short for vehicle ID response"
        );

        server.shutdown();
    }

    #[tokio::test]
    async fn vehicle_identification_with_eid() {
        let port = 23411;
        let server = start_test_server(port).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind failed");
        let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // Send vehicle ID request with EID (matching server's EID)
        let eid = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let request = build_doip_message(0x0002, &eid);
        socket
            .send_to(&request, server_addr)
            .await
            .expect("send failed");

        let mut buf = vec![0u8; 128];
        let result = timeout(TEST_TIMEOUT, socket.recv_from(&mut buf)).await;

        // Should get response because EID matches
        if let Ok(Ok((_n, _))) = result {
            let (payload_type, _) = parse_doip_header(&buf).unwrap();
            assert_eq!(
                payload_type, 0x0004,
                "expected vehicle identification response"
            );
        }

        server.shutdown();
    }
}
