<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# DoIP Server — TODO and Future Work

This document tracks implementation TODOs and future improvements for the current DoIP server.
It is aligned with the present codebase (stub backend, synchronous proxy contract, and startup-time configuration loading).

---

## A) TODOs

### A1. Replace `StubProxy` with real backend integration


**Why**
- Diagnostic forwarding currently ends at `StubProxy`.
- Real UDS-to-SOVD execution path is not available.

**Actions**
- Implement production `SovdProxy` integration.
- Add backend configuration and connection handling.
- Validate end-to-end diagnostic flows.

### A2. Improve shutdown control model

**Why**
- Shutdown is currently triggered by `Ctrl+C`.
- Signal handling should be extensible.

**Actions**
- Support additional termination signals.
- Add programmatic shutdown trigger.
- Add graceful drain behaviour before full stop.

### A3. Add CLI argument parsing

**Why**
- Current startup argument handling can be improved for usability.

**Actions**
- Introduce argument parser (`clap` or equivalent).
- Improve argument validation and error messages.
- Standardize help output and startup options.

### A4. Add future configuration sources

**Why**
- Current providers cover defaults and TOML.
- Future deployments may require alternative sources.

**Actions**
- Add environment-variable provider.
- Evaluate remote configuration service integration.
- Keep the `ConfigProvider` abstraction unchanged.

### A5. Code quality improvement candidates


**Why**
- Repeated constructor-style patterns may appear as the codebase grows.

**Actions**
- Consider `#[derive(new)]` where it improves consistency.
- Apply only when it reduces boilerplate without harming readability.

### A6. Routing activation state machine



**Why**
- Routing activation is currently handled by a simple success response handler.
- A protocol-aware state machine is still missing.

**Actions**
- Model routing activation states and transitions.
- Validate activation requests against the current session context.
- Return protocol-correct activation responses and failures.

---

## B) High-priority roadmap

### B1. Asynchronous backend processing



**Why**
- `SovdProxy::process()` is synchronous.
- Future backend I/O can block and reduce throughput.

**Actions**
- Introduce async backend contract.
- Update diagnostic handling path to async flow.
- Add integration tests for latency and backpressure.

### B2. UDS Response Pending support (`0x78`)



**Why**
- Current flow assumes immediate request/response.
- Long-running diagnostics need response-pending behaviour.

**Actions**
- Add response-pending handling in diagnostic path.
- Validate client interoperability for delayed completion.

### B3. TLS-secured DoIP transport



**Why**
- Current transport is not encrypted.

**Actions**
- Define TLS architecture.
- Add certificate and key management.
- Validate secure client interoperability.

---

## C) Medium-priority roadmap

### C1. Additional DoIP message support



**Actions**
- Expand handler coverage for required ISO 13400-2 flows.
- Add protocol compatibility tests.

### C2. Observability improvements



**Actions**
- Improve structured logs and request correlation.
- Add runtime metrics (connection/session/protocol counters).

### C3. Configuration validation hardening



**Actions**
- Strengthen startup validation and error reporting.
- Add invalid-configuration test coverage.

---

## D) Deferred items

### D1. Persistent runtime state

Deferred

**Reason**
- Current design intentionally uses in-memory runtime state.

### D2. Multi-entity support

Deferred

**Reason**
- Current deployment model assumes one DoIP entity per instance.

### D3. Distributed deployment support

Deferred

**Reason**
- Current architecture targets single-process operation.

---