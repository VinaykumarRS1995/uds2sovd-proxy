# DoIP Server POC

DoIP (Diagnostics over IP) Server implementation following ISO 13400-2.

## Features

- TCP diagnostic communication (port 13400)
- UDP vehicle discovery (port 13400)
- Routing activation with session management
- Diagnostic message handling with UDS transport
- Async implementation with Tokio
- Configurable via CLI or TOML file

## Build

```bash
cargo build --release
```

## Run

```bash
# Default settings
cargo run

# With config file
cargo run -- -c config.toml

# Custom settings
cargo run -- --port 13401 --logical-address 0x1000

# Debug logging
RUST_LOG=debug cargo run
```

## Test

```bash
# Unit tests
cargo test

# Test client (requires server running)
cargo run --bin test_client
```

## Project Structure

```
src/
├── main.rs           # Server entry point
├── lib.rs            # Library exports
├── error.rs          # Error types
├── bin/
│   └── test_client.rs  # Test client
├── doip/
│   ├── hearder_parser.rs    # DoIP header + codec
│   ├── routing_activation.rs # Session establishment
│   ├── diagnostic_message.rs # UDS transport
│   ├── vehicle_id.rs         # UDP discovery
│   └── alive_check.rs        # Keep-alive
└── server/
    ├── config.rs      # Server configuration
    ├── session.rs     # Session management
    ├── tcp_handler.rs # TCP connection handler
    └── udp_handler.rs # UDP discovery handler
```

## Configuration

See [config.toml](config.toml) for example configuration.

## Protocol Support

| Message Type | Payload Type | Status |
|--------------|-------------|--------|
| Vehicle ID Request | 0x0001 | Supported |
| Vehicle ID with EID | 0x0002 | Supported |
| Vehicle ID with VIN | 0x0003 | Supported |
| Vehicle ID Response | 0x0004 | Supported |
| Routing Activation Request | 0x0005 | Supported |
| Routing Activation Response | 0x0006 | Supported |
| Alive Check Request | 0x0007 | Supported |
| Alive Check Response | 0x0008 | Supported |
| Diagnostic Message | 0x8001 | Supported |
| Diagnostic Positive Ack | 0x8002 | Supported |
| Diagnostic Negative Ack | 0x8003 | Supported |
