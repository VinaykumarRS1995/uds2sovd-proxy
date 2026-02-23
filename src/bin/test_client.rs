// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation

//! `DoIP` Test Client

use bytes::{BufMut, BytesMut};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

const HOST: &str = "127.0.0.1";
const PORT: u16 = 13400;

// Payload types
const VEHICLE_ID_REQUEST: u16 = 0x0001;
const VEHICLE_ID_RESPONSE: u16 = 0x0004;
const ROUTING_ACTIVATION_REQUEST: u16 = 0x0005;
const ROUTING_ACTIVATION_RESPONSE: u16 = 0x0006;
const DIAGNOSTIC_MESSAGE: u16 = 0x8001;
const DIAGNOSTIC_POSITIVE_ACK: u16 = 0x8002;
const DIAGNOSTIC_NEGATIVE_ACK: u16 = 0x8003;

fn build_doip_message(payload_type: u16, payload: &[u8]) -> Vec<u8> {
    let capacity = 8_usize.saturating_add(payload.len());
    let mut buf = BytesMut::with_capacity(capacity);
    buf.put_u8(0x02); // Version
    buf.put_u8(0xFD); // Inverse version
    buf.put_u16(payload_type);
    buf.put_u32(
        u32::try_from(payload.len()).expect("payload exceeds u32::MAX"),
    );
    buf.put_slice(payload);
    buf.to_vec()
}

fn parse_doip_header(data: &[u8]) -> Option<(u16, u32)> {
    if data.len() < 8 {
        return None;
    }
    let payload_type = u16::from_be_bytes([*data.get(2)?, *data.get(3)?]);
    let payload_len =
        u32::from_be_bytes([*data.get(4)?, *data.get(5)?, *data.get(6)?, *data.get(7)?]);
    Some((payload_type, payload_len))
}

fn test_udp_vehicle_discovery() -> std::io::Result<()> {
    println!("\n{}", "=".repeat(50));
    println!("UDP Vehicle Discovery Test");
    println!("{}", "=".repeat(50));

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let request = build_doip_message(VEHICLE_ID_REQUEST, &[]);
    let target = format!("{HOST}:{PORT}");

    println!("Sending: {}", hex_encode(&request));
    socket.send_to(&request, &target)?;

    let mut buf = [0u8; 256];
    match socket.recv_from(&mut buf) {
        Ok((len, addr)) => {
            println!("Response from {addr}:");
            println!("  Raw: {}", hex_encode(buf.get(..len).unwrap_or(&[])));

            if let Some((payload_type, _)) = parse_doip_header(buf.get(..len).unwrap_or(&[])) {
                if payload_type == VEHICLE_ID_RESPONSE && len >= 40 {
                    println!("  Status: SUCCESS");
                    let vin = String::from_utf8_lossy(buf.get(8..25).unwrap_or(&[]));
                    let logical_addr = u16::from_be_bytes([
                        *buf.get(25).unwrap_or(&0),
                        *buf.get(26).unwrap_or(&0),
                    ]);
                    let eid = hex_encode(buf.get(27..33).unwrap_or(&[]));
                    let gid = hex_encode(buf.get(33..39).unwrap_or(&[]));
                    println!("  VIN: {vin}");
                    println!("  Logical Address: 0x{logical_addr:04X}");
                    println!("  EID: {eid}");
                    println!("  GID: {gid}");
                } else {
                    println!("  Unexpected response type: 0x{payload_type:04X}");
                }
            }
        }
        Err(e) => {
            println!("  Status: TIMEOUT ({e})");
        }
    }

    Ok(())
}

fn test_tcp_routing_activation() -> std::io::Result<TcpStream> {
    println!("\n{}", "=".repeat(50));
    println!("TCP Routing Activation Test");
    println!("{}", "=".repeat(50));

    let mut stream = TcpStream::connect(format!("{HOST}:{PORT}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    println!("Connected to {HOST}:{PORT}");

    // Source address: 0x0E00, Activation type: 0x00, Reserved: 4 bytes
    let payload = [0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let request = build_doip_message(ROUTING_ACTIVATION_REQUEST, &payload);

    println!("Sending: {}", hex_encode(&request));
    stream.write_all(&request)?;

    let mut buf = [0u8; 256];
    let len = stream.read(&mut buf)?;
    println!("Response: {}", hex_encode(buf.get(..len).unwrap_or(&[])));

    if let Some((payload_type, _)) = parse_doip_header(buf.get(..len).unwrap_or(&[])) {
        if payload_type == ROUTING_ACTIVATION_RESPONSE && len >= 13 {
            let tester_addr =
                u16::from_be_bytes([*buf.get(8).unwrap_or(&0), *buf.get(9).unwrap_or(&0)]);
            let entity_addr =
                u16::from_be_bytes([*buf.get(10).unwrap_or(&0), *buf.get(11).unwrap_or(&0)]);
            let code = *buf.get(12).unwrap_or(&0);

            let code_str = match code {
                0x00 => "Unknown source address",
                0x01 => "All sockets registered",
                0x02 => "Different source address",
                0x03 => "Source address already active",
                0x04 => "Missing authentication",
                0x05 => "Rejected confirmation",
                0x06 => "Unsupported activation type",
                0x10 => "Successfully activated",
                0x11 => "Confirmation required",
                _ => "Unknown",
            };

            let status = if code == 0x10 { "SUCCESS" } else { "FAILED" };
            println!("  Status: {status}");
            println!("  Tester Address: 0x{tester_addr:04X}");
            println!("  Entity Address: 0x{entity_addr:04X}");
            println!("  Response Code: 0x{code:02X} ({code_str})");
        }
    }

    Ok(stream)
}

fn test_tcp_diagnostic_tester_present(stream: &mut TcpStream) -> std::io::Result<()> {
    println!("\n{}", "=".repeat(50));
    println!("TCP Diagnostic Message Test (TesterPresent)");
    println!("{}", "=".repeat(50));

    // SA: 0x0E00, TA: 0x1000, UDS: TesterPresent (0x3E 0x00)
    let payload = [0x0E, 0x00, 0x10, 0x00, 0x3E, 0x00];
    let request = build_doip_message(DIAGNOSTIC_MESSAGE, &payload);

    println!("Sending TesterPresent (0x3E): {}", hex_encode(&request));
    stream.write_all(&request)?;

    let mut buf = [0u8; 256];
    let len = stream.read(&mut buf)?;
    println!("Response: {}", hex_encode(buf.get(..len).unwrap_or(&[])));

    if let Some((payload_type, _)) = parse_doip_header(buf.get(..len).unwrap_or(&[])) {
        match payload_type {
            DIAGNOSTIC_MESSAGE => {
                if len >= 12 {
                    let sa =
                        u16::from_be_bytes([*buf.get(8).unwrap_or(&0), *buf.get(9).unwrap_or(&0)]);
                    let ta = u16::from_be_bytes([
                        *buf.get(10).unwrap_or(&0),
                        *buf.get(11).unwrap_or(&0),
                    ]);
                    let uds = buf.get(12..len).unwrap_or(&[]);
                    println!("  Status: DIAGNOSTIC RESPONSE");
                    println!("  SA: 0x{sa:04X}, TA: 0x{ta:04X}");
                    println!("  UDS Response: {}", hex_encode(uds));

                    if !uds.is_empty() {
                        if uds.first() == Some(&0x7F) && uds.len() >= 3 {
                            println!(
                                "    -> Negative Response: NRC 0x{:02X}",
                                uds.get(2).unwrap_or(&0)
                            );
                        } else if uds.first() == Some(&0x7E) {
                            println!("    -> Positive TesterPresent Response");
                        }
                    }
                }
            }
            DIAGNOSTIC_POSITIVE_ACK => {
                println!("  Status: POSITIVE ACK");
            }
            DIAGNOSTIC_NEGATIVE_ACK => {
                println!("  Status: NEGATIVE ACK");
            }
            _ => {
                println!("  Unexpected response type: 0x{payload_type:04X}");
            }
        }
    }

    Ok(())
}

fn test_tcp_read_data_by_id(stream: &mut TcpStream) -> std::io::Result<()> {
    println!("\n{}", "=".repeat(50));
    println!("TCP Read Data By Identifier (UDS 0x22 F190)");
    println!("{}", "=".repeat(50));

    // SA: 0x0E00, TA: 0x1000, UDS: ReadDataByIdentifier VIN (0x22 F1 90)
    let payload = [0x0E, 0x00, 0x10, 0x00, 0x22, 0xF1, 0x90];
    let request = build_doip_message(DIAGNOSTIC_MESSAGE, &payload);

    println!("Sending ReadVIN (0x22 F190): {}", hex_encode(&request));
    stream.write_all(&request)?;

    let mut buf = [0u8; 256];
    let len = stream.read(&mut buf)?;
    println!("Response: {}", hex_encode(buf.get(..len).unwrap_or(&[])));

    if let Some((payload_type, _)) = parse_doip_header(buf.get(..len).unwrap_or(&[])) {
        if payload_type == DIAGNOSTIC_MESSAGE && len >= 12 {
            let uds = buf.get(12..len).unwrap_or(&[]);
            println!("  UDS Response: {}", hex_encode(uds));

            if !uds.is_empty() {
                if uds.first() == Some(&0x62) && uds.len() >= 20 {
                    // Positive response: 0x62 + DID + Data
                    let vin = String::from_utf8_lossy(uds.get(3..20).unwrap_or(&[]));
                    println!("    -> VIN: {vin}");
                } else if uds.first() == Some(&0x7F) && uds.len() >= 3 {
                    println!(
                        "    -> Negative Response: NRC 0x{:02X}",
                        uds.get(2).unwrap_or(&0)
                    );
                }
            }
        }
    }

    Ok(())
}

fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn main() {
    println!("\n{}", "#".repeat(50));
    println!("# DoIP Server Test Client (Rust)");
    println!("{}", "#".repeat(50));
    println!("Target: {HOST}:{PORT}");

    // Test 1: UDP Discovery
    if let Err(e) = test_udp_vehicle_discovery() {
        eprintln!("UDP test failed: {e}");
    }

    std::thread::sleep(Duration::from_millis(500));

    // Test 2: TCP Routing + Diagnostic
    match test_tcp_routing_activation() {
        Ok(mut stream) => {
            std::thread::sleep(Duration::from_millis(300));

            if let Err(e) = test_tcp_diagnostic_tester_present(&mut stream) {
                eprintln!("Diagnostic test failed: {e}");
            }

            std::thread::sleep(Duration::from_millis(300));

            if let Err(e) = test_tcp_read_data_by_id(&mut stream) {
                eprintln!("Read VIN test failed: {e}");
            }
        }
        Err(e) => {
            eprintln!("TCP test failed: {e}");
        }
    }

    println!("\n{}", "=".repeat(50));
    println!("Tests Complete");
    println!("{}", "=".repeat(50));
}
