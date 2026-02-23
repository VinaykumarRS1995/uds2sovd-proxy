# Code Style Guide - Eclipse DoIP Server

This document defines the coding standards for the Eclipse DoIP Server project.

## Table of Contents

- [General Principles](#general-principles)
- [Formatting](#formatting)
- [Naming Conventions](#naming-conventions)
- [Documentation](#documentation)
- [Error Handling](#error-handling)
- [Safety Guidelines](#safety-guidelines)
- [Protocol Standards](#protocol-standards)
- [Testing](#testing)
- [Tooling](#tooling)

## General Principles

1. **Clarity over cleverness** - Write readable, maintainable code
2. **Safety first** - No unsafe code without justification
3. **Standards compliance** - Follow ISO 13400-2 and ISO 14229-1
4. **Idiomatic Rust** - Use Rust conventions and patterns

## Formatting

### Rustfmt Configuration

All code must be formatted with `cargo fmt`. Configuration in `rustfmt.toml`:

```toml
max_width = 100
edition = "2021"
```

### Line Length

- Maximum 100 characters per line
- Break long function signatures appropriately:

```rust
// ✅ Good
fn handle_routing_activation(
    &self,
    session_id: u64,
    payload: Bytes,
    version: u8,
) -> HandleResult {
    // ...
}
```

### Imports

- Group imports: std, external crates, crate modules
- Use `use` statements at module top
- Prefer specific imports over wildcards

```rust
// ✅ Good
use std::sync::Arc;
use tokio::net::TcpStream;
use crate::doip::header_parser::DoipMessage;

// ❌ Avoid
use crate::doip::*;
```

## Naming Conventions

### General Rules

| Item | Convention | Example |
|------|------------|---------|
| Types | PascalCase | `SessionManager` |
| Functions | snake_case | `handle_message` |
| Constants | SCREAMING_SNAKE | `MAX_MESSAGE_SIZE` |
| Modules | snake_case | `header_parser` |
| Lifetimes | short lowercase | `'a`, `'buf` |

### Protocol-Specific

- Use ISO terminology where applicable
- Prefix DoIP types appropriately

```rust
// ✅ Good - matches ISO 13400-2 terminology
pub enum PayloadType { ... }
pub struct RoutingActivationRequest { ... }

// ✅ Good - clear protocol context
pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
```

## Documentation

### Module Documentation

```rust
//! Brief description of module purpose.
//!
//! More detailed explanation of functionality,
//! relevant ISO standards, and usage context.
```

### Function Documentation

```rust
/// Brief one-line description.
///
/// Detailed explanation of behavior, including
/// protocol context where relevant.
///
/// # Arguments
///
/// * `payload` - Raw bytes to parse (minimum 7 bytes)
///
/// # Returns
///
/// Parsed request on success.
///
/// # Errors
///
/// Returns error if:
/// * Payload is too short
/// * Invalid activation type
///
/// # Examples
///
/// ```
/// use doip_server::doip::routing_activation::Request;
/// let request = Request::parse(&payload)?;
/// ```
#[must_use]
pub fn parse(payload: &[u8]) -> Result<Self, Error> {
    // ...
}
```

### Required Annotations

- `#[must_use]` on all pure functions and constructors
- `# Errors` section for all `Result<T, E>` returns
- ISO standard references for protocol types

### Code Comments

```rust
// ✅ Good - explains WHY
// Safe cast: DoIP messages are limited to 4MB which fits in u32
#[allow(clippy::cast_possible_truncation)]
payload_length: payload.len() as u32,

// ❌ Bad - explains WHAT (obvious from code)
// Increment counter by 1
counter += 1;
```

## Error Handling

### Error Types

Use `thiserror` for structured errors:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Payload too short: expected {expected}, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },
    
    #[error("Invalid activation type: 0x{0:02X}")]
    InvalidActivationType(u8),
}
```

### Result Handling

```rust
// ✅ Good - use ? operator
let header = DoipHeader::parse(buf)?;

// ✅ Good - use let-else for early return
let Some(session) = self.sessions.get(id) else {
    return Err(Error::SessionNotFound);
};

// ❌ Avoid - unwrap in production code
let value = option.unwrap();
```

### Production Code Rules

- **No `unwrap()`** - Use `?`, `expect()`, or handle explicitly
- **No `panic!()`** - Return errors instead
- **No direct indexing** - Use `.get()` with bounds checking

## Safety Guidelines

### Memory Safety

```rust
// ✅ Good - safe indexing
let value = buffer.get(index).ok_or(Error::OutOfBounds)?;

// ✅ Good - checked arithmetic
let total = a.saturating_add(b);

// ❌ Avoid - may panic
let value = buffer[index];
let total = a + b; // May overflow
```

### Concurrency

```rust
// ✅ Good - explicit Arc cloning
let handler = Arc::clone(&self.handler);

// ✅ Good - use parking_lot for performance
use parking_lot::RwLock;

// ❌ Avoid - implicit clone
let handler = self.handler.clone();
```

### Async Code

```rust
// ✅ Good - only async when awaiting
pub async fn fetch_data(&self) -> Result<Data> {
    self.client.get().await?
}

// ✅ Good - sync when no await needed
pub fn validate(&self) -> bool {
    self.data.is_valid()
}
```

## Protocol Standards

### ISO References

All protocol structures must reference ISO standards:

```rust
/// Routing activation types per ISO 13400-2 Table 24
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationType {
    /// Default activation (0x00)
    Default = 0x00,
    /// WWH-OBD activation (0x01)
    WwhObd = 0x01,
}
```

### Version Handling

```rust
/// Protocol version per ISO 13400-2:2019 Section 6
pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
```

### Message Limits

```rust
/// Maximum DoIP message size per ISO 13400-2
pub const MAX_DOIP_MESSAGE_SIZE: u32 = 0x0040_0000; // 4MB
```

## Testing

### Test Organization

```rust
#[cfg(test)]
#[allow(clippy::indexing_slicing)] // Safe in tests with controlled data
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_request() {
        // Arrange
        let payload = [0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // Act
        let result = Request::parse(&payload);
        
        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_short_payload_returns_error() {
        let payload = [0x0E, 0x00];
        let result = Request::parse(&payload);
        assert!(matches!(result, Err(Error::PayloadTooShort { .. })));
    }
}
```

### Test Naming

Format: `test_<function>_<scenario>_<expected_outcome>`

```rust
#[test]
fn test_parse_valid_header_returns_message() { }

#[test]
fn test_parse_invalid_version_returns_error() { }
```

### Test Allowances

In test code, these are allowed:
- `.unwrap()` and `.expect()`
- Direct indexing (with `#[allow(clippy::indexing_slicing)]`)
- `panic!()` for test assertions

## Tooling

### Required Tools

```bash
# Install required components
rustup component add clippy rustfmt
cargo install cargo-deny

# Optional but recommended
pip install pre-commit
```

### Pre-commit Checks

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --all-targets

# Test
cargo test

# License check
cargo deny check licenses
```

### Clippy Configuration

See `clippy.toml`:
- Pedantic mode enabled
- 130 line function limit
- Unwrap allowed in tests

## License Headers

All source files require:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation
```

---

## Quick Reference

| Rule | Command |
|------|---------|
| Format code | `cargo fmt --all` |
| Check lints | `cargo clippy --all-targets` |
| Run tests | `cargo test` |
| Check licenses | `cargo deny check licenses` |
| Build release | `cargo build --release` |
