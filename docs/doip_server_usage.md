<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# DoIP Server — Usage Guide

This document explains how to build, configure, run, and troubleshoot the DoIP server in this repository.

For architecture and design details, see [HIGH_LEVEL_DESIGN.md](doip_server_high_level_design_detail.md)
---

# Prerequisites

## Software Requirements

- Rust stable toolchain
- Cargo
- Git

Verify installation:

```bash
rustc --version
cargo --version
```

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
cd <repository>
```

---

# Build

Build the workspace:

```bash
cargo build
```

Build the DoIP server binary only:

```bash
cargo build -p doip-server
```

Build optimized release binaries:

```bash
cargo build --release
```

---

# Configuration

The server supports two configuration modes:

- Default configuration
- TOML configuration file

## Default Configuration

Run the server without arguments to use the built-in defaults:

```bash
cargo run -p doip-server
```

The default configuration is defined in the code and uses:
- TCP listener on `127.0.0.1:13400`
- UDP listener on `0.0.0.0:13400`
- Maximum TCP sessions: `10`
- TCP read buffer size: `4096`
- Logical address: `0x0001`
- Default VIN, EID, and GID values from the server defaults

---

## TOML Configuration

Run the server with a TOML configuration file path as the first positional argument:

```bash
cargo run -p doip-server -- app/sample-doip-server.toml
```

The sample configuration file is provided at [app/sample-doip-server.toml](../app/sample-doip-server.toml).

You can also run from the `app/` directory:

```bash
cd app
cargo run -- sample-doip-server.toml
```

Example configuration:

```toml
[tcp]
address = "127.0.0.1:13400"
max_connections = 10
logical_address = 1
read_buffer_size = 4096

[udp]
address = "0.0.0.0:13400"
logical_address = 1

[ecu]
logical_address = 1
vin = [48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48]
eid = [0, 0, 0, 0, 0, 0]
gid = [0, 0, 0, 0, 0, 0]
```

Both configuration modes provide the same runtime behaviour once the server starts.

---

# Validate Build

Before running the server, validate formatting, linting, and tests:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

---

# Running

## Start Server

Using defaults:

```bash
cargo run -p doip-server
```

Using the sample TOML configuration:

```bash
cargo run -p doip-server -- app/sample-doip-server.toml
```

Expected startup output:

```text
Starting DoIP server
TCP server listening
UDP server listening
```

---

# Typical Workflows

## Vehicle Discovery

1. Start the server with the default configuration or the sample TOML file
2. Send a DoIP vehicle identification request
3. Receive vehicle announcement response

Expected result:

```text
Vehicle identification response
```

---

## Routing Activation

1. Establish a TCP connection
2. Send Routing Activation Request
3. Receive Routing Activation Response

Expected result:

```text
RoutingActivationResponse frame
```

---

## Diagnostic Communication

1. Establish routing activation
2. Send Diagnostic Message
3. Server forwards request to backend proxy
4. Receive diagnostic response

Expected result:

```text
Diagnostic response received
```

Note:

The current implementation uses a stub backend, so diagnostic requests return a negative response until a real backend is added. Refer to [LIMITATIONS.md](doip_server_limitation.md).

---

# Logging

The server uses structured logging through the Rust tracing ecosystem.

Typical log output includes:

```text
Starting DoIP server
TCP server listening
UDP server listening
new TCP connection
client disconnected
UDP dispatch error
```

Logging output is useful for:

* Startup validation
* Connection monitoring
* Protocol troubleshooting
* Error diagnosis

---

# Troubleshooting

## Server Does Not Start

Possible causes:

- Port already in use
- Invalid configuration
- Configuration file not found

Check:

```bash
cargo run -p doip-server -- app/sample-doip-server.toml
```

and review startup logs.

---

## TCP Connection Rejected

Possible causes:

- Maximum session limit reached

Check:

- Current session limit in the configuration
- Active client connections

---

## No Vehicle Discovery Response

Possible causes:

- VIN mismatch
- EID mismatch
- Incorrect network configuration

Verify:

- ECU configuration in the TOML file or default values
- UDP connectivity
- Discovery request contents

---

## Protocol Errors

Possible causes:

- Invalid DoIP message format
- Unsupported payload type
- Incorrect protocol version

Review server logs for details.

---

## Diagnostic Requests Always Fail

Current behaviour:

The server uses a stub backend implementation.

Verify:

- Request reaches `DiagnosticsHandler`
- Stub response is received

Refer to [LIMITATIONS.md](doip_server_limitation.md).

---

# Development Workflow

## Format

```bash
cargo fmt
```

---

## Lint

```bash
cargo clippy --all-targets --all-features
```

---

## Run Tests

```bash
cargo test
```

---

## Generate Documentation

```bash
cargo doc --no-deps
```

---

## Sample Configuration File

The repository includes a ready-to-run sample configuration at [app/sample-doip-server.toml](../app/sample-doip-server.toml).

Use it as-is for local testing:

```bash
cargo run -p doip-server -- app/sample-doip-server.toml
```

Use it as a template when creating your own configuration file:

```bash
cp app/sample-doip-server.toml my-doip-server.toml
cargo run -p doip-server -- my-doip-server.toml
```

---

# Related Documentation

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Project overview and getting started |
| [HIGH LEVEL DESIGN](doip_server_high_level_design_detail.md) | Architecture and design overview |
| [LIMITATIONS](doip_server_limitation.md) | Known limitations and constraints |
| [TODO](doip_server_todo.md) | Planned enhancements and roadmap |

---

