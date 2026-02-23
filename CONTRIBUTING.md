# Contributing to Eclipse DoIP Server

Thank you for your interest in contributing to the Eclipse DoIP Server project!

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Eclipse Contributor Agreement](#eclipse-contributor-agreement)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [License](#license)

## Code of Conduct

This project follows the [Eclipse Community Code of Conduct](https://www.eclipse.org/org/documents/Community_Code_of_Conduct.php).
By participating, you are expected to uphold this code.

## Eclipse Contributor Agreement

Before your contribution can be accepted by the project, you need to create and
electronically sign the [Eclipse Contributor Agreement (ECA)](https://www.eclipse.org/legal/ECA.php).

The ECA provides the Eclipse Foundation with a permanent record that you agree
that each of your contributions will comply with the commitments documented in
the Developer Certificate of Origin (DCO).

## Development Setup

### Prerequisites

- Rust 1.75+ (stable)
- Cargo (comes with Rust)

### Setup Steps

```bash
# Clone the repository
git clone https://github.com/eclipse-uprotocol/doip-server.git
cd doip-server

# Install development tools
cargo install cargo-deny
rustup component add clippy rustfmt

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install

# Build the project
cargo build

# Run tests
cargo test
```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Rust version (`rustc --version`)
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs/error messages

### Suggesting Features

1. Check existing issues and discussions
2. Open a feature request issue
3. Describe the use case and expected behavior
4. Reference relevant ISO 13400-2 sections if applicable

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes following [coding standards](#coding-standards)
4. Add tests for new functionality
5. Run the verification checklist
6. Submit a pull request

## Pull Request Process

### Before Submitting

Run the complete verification checklist:

```bash
# 1. Format code
cargo fmt --all

# 2. Run clippy
cargo clippy --all-targets

# 3. Run tests
cargo test

# 4. Check licenses
cargo deny check licenses

# 5. Build release
cargo build --release

# 6. Integration tests
cargo test --test integration_tests
```

### PR Requirements

- [ ] All CI checks pass
- [ ] Code is formatted with `cargo fmt`
- [ ] No new clippy warnings
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated if needed
- [ ] SPDX license header on new files
- [ ] Commit messages follow conventions
- [ ] Signed-off-by line present (DCO)

### Commit Message Format

```
type: Short description (max 50 chars)

Longer description explaining the change, motivation,
and any relevant context. Wrap at 72 characters.

Refs: #issue-number
Signed-off-by: Your Name <your.email@example.com>
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code restructuring
- `test:` - Test additions/changes
- `chore:` - Maintenance tasks

### Review Process

1. Maintainers will review within 5 business days
2. Address feedback in new commits
3. Squash commits before merge if requested
4. PRs require at least one approval

## Coding Standards

See [CODESTYLE.md](CODESTYLE.md) for detailed coding standards.

### Quick Summary

- Follow Rust idioms and best practices
- Use `cargo fmt` for formatting (max 100 chars)
- Pass `cargo clippy --all-targets` without errors
- Add `#[must_use]` to pure functions
- Document public APIs with `///` comments
- Include `# Errors` section for Result-returning functions
- Reference ISO standards where applicable
- No `unsafe` code without justification

### License Headers

All source files must have SPDX headers:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Contributors to the Eclipse Foundation
```

## Testing Requirements

### Unit Tests

- Test all public functions
- Cover error paths
- Use descriptive test names: `test_<function>_<scenario>`

### Integration Tests

- Test end-to-end flows
- Located in `tests/` directory

### Test Coverage

- Aim for >80% code coverage on new code
- All PR additions must include tests

## License

By contributing, you agree that your contributions will be licensed under
the Apache License, Version 2.0.

## Questions?

- Open a GitHub issue for questions
- Join the Eclipse uProtocol community discussions
- Contact the project maintainers

Thank you for contributing! 🚀
