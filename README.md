
<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# 🔌 UDS-to-SOVD Proxy 

This repository contains the UDS-to-SOVD Proxy of the [Eclipse OpenSOVD](https://github.com/eclipse-opensovd/uds2sovd-proxy) project.

In the SOVD (Service-Oriented Vehicle Diagnostics) context, the UDS-to-SOVD Proxy serves as a protocol translation gateway between legacy UDS (Unified Diagnostic Services) based diagnostic tools and the modern SOVD-based diagnostic architecture.

It accepts UDS requests over DoIP (Diagnostics over IP, [ISO 13400-2](https://www.iso.org/standard/74785.html)), resolves the corresponding SOVD service using the diagnostic description (MDD) of the ECU, and translates them into SOVD REST API calls. The SOVD responses are then encoded back into UDS format and returned to the requesting tool.

```
                      ┌──────────────────────────────────┐
                      │          uds2sovd-proxy          │
                      │                                  │
┌──────────┐  DoIP    │  ┌──────────┐   ┌─────────────┐  │     ┌─────────┐
│Diagnostic│◄────────►│  │  DoIP    │──►│  UDS2SOVD   │──┼────►│  SOVD   │
│  Tester  │ TCP/UDP  │  │ Server   │   │UDS↔SOVD/REST│  │     │ Backend │
└──────────┘  :13400  │  └──────────┘   └─────────────┘  │     └─────────┘
                      │                                  │
                      └──────────────────────────────────┘
```

> **Project status:** The UDS2SOVD translation layer currently returns NRC 0x11 (serviceNotSupported) for all diagnostic requests (StubProxy). Real SOVD integration is under development.

## goals

- transparent UDS ↔ SOVD protocol translation
- high performance (asynchronous I/O)
- low memory and disk-space consumption
- safe & secure
- fast startup

## introduction

The proxy consists of a **DoIP Server** (handles the DoIP wire protocol over TCP :13400 / UDP :13400) and the **UDS2SOVD translation layer** (translates UDS request bytes into SOVD REST API calls using the ECU's MDD diagnostic description).

**Discovery** happens over UDP — testers broadcast vehicle identification requests and the server responds with its VIN, EID, and logical address. **Diagnostics** happen over TCP — after a routing activation handshake, the tester sends UDS requests which the server forwards to the UDS2SOVD layer.

### supported messages

| Payload Type | Name | Transport | Behavior |
|-------------|------|-----------|----------|
| 0x0001 | VehicleIdentificationRequest | UDP | Announces this entity |
| 0x0002 | VehicleIdentificationByEID | UDP | Responds if EID matches, silent otherwise (ISO §7.6.1) |
| 0x0003 | VehicleIdentificationByVIN | UDP | Responds if VIN matches, silent otherwise (ISO §7.6.1) |
| 0x4001 | EntityStatusRequest | UDP | Reports node type and capacity |
| 0x0005 | RoutingActivationRequest | TCP | Accepts handshake |
| 0x0007 | AliveCheckRequest | TCP | Confirms connection is live |
| 0x8001 | DiagnosticMessage | TCP | Forwards UDS payload, returns ECU response |

### usage

1. Run with defaults (TCP `127.0.0.1:13400`, UDP `0.0.0.0:13400`):
   ```sh
   cargo run
   ```
2. Or with a TOML config file:
   ```sh
   cargo run -- path/to/config.toml
   ```
3. Verify with the E2E tester (proxy must be running):
   ```sh
   cargo run --example doip_tester
   ```

### configuration

If no config file is passed, sensible defaults are used:

| Setting | Default | Description |
|---------|---------|-------------|
| TCP address | `127.0.0.1:13400` | Where TCP clients connect |
| UDP address | `0.0.0.0:13400` | Where UDP broadcasts are received |
| Max connections | `10` | Concurrent TCP sessions |
| Read buffer | `4096` bytes | TCP read chunk size |
| Logical address | `0x0001` | DoIP entity address |
| VIN | `00000000000000000` | Vehicle Identification Number |
| EID | `00:00:00:00:00:00` | Entity ID (MAC address) |
| GID | `00:00:00:00:00:00` | Group ID |

## building

### prerequisites

Rust toolchain ≥ 1.85 — install via [rustup](https://rustup.rs/).

### build the executable

```sh
cargo build --release
```

## developing

### pre commit

```sh
uv run https://raw.githubusercontent.com/eclipse-opensovd/cicd-workflows/main/run_checks.py
```

### codestyle

see [codestyle](CODESTYLE.md)

### testing

#### unit tests

Unittests are placed in the relevant module as usual in rust:
```rust
...
#[cfg(test)]
mod tests {
    ...
}
```

Run unit tests with:
```sh
cargo test --locked --lib
```

#### integration tests

Start the proxy, then run the E2E tester:
```sh
cargo run &
cargo run --example doip_tester
```

## license

Apache-2.0 — see [LICENSE](LICENSE).

