# Contributing to R-VPN

Thank you for your interest in contributing to R-VPN! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Issues](#security-issues)
- [Licensing](#licensing)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive criticism
- Accept responsibility and apologize when mistakes happen
- Prioritize the security and privacy of users

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up the development environment** (see below)
4. **Create a branch** for your changes
5. **Make your changes** following our guidelines
6. **Submit a pull request**

## How to Contribute

### Reporting Bugs

Before creating a bug report, please:

- Check if the issue already exists
- Use the latest version to verify the bug still exists
- Collect information about the bug (logs, configuration, steps to reproduce)

When reporting bugs, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, architecture, versions)
- **Logs or error messages** (redact sensitive information)

### Suggesting Features

We welcome feature suggestions! Please:

- Check if the feature has already been suggested
- Explain the use case and why it would be valuable
- Consider how it fits with R-VPN's privacy-focused design
- Be open to discussion and alternative approaches

### Contributing Code

Areas where contributions are especially welcome:

- **Security improvements** - Cryptographic hardening, audit fixes
- **Performance optimizations** - Faster encryption, lower latency
- **Platform support** - New operating systems, architectures
- **Documentation** - Better explanations, tutorials, translations
- **Testing** - Unit tests, integration tests, fuzzing
- **Bug fixes** - Addressing open issues

## Development Setup

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- Cargo
- Git
- OpenSSL development libraries

### Building

```bash
# Clone the repository
git clone https://github.com/creativebastard/rvpn.git
cd rvpn

# Build the client
cargo build --release --bin rvpn

# Build the server
cargo build --release --bin rvpn-server

# Run tests
cargo test --all
```

### Cross-Compilation

For ARM targets (routers, embedded):

```bash
# Install cross-compilation tool
cargo install cross

# Build for ARM64
cross build --release --target aarch64-unknown-linux-gnu

# Build for ARMv7
cross build --release --target armv7-unknown-linux-gnueabihf
```

## Coding Standards

### Rust Guidelines

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` to format code
- Use `cargo clippy` and address warnings
- Write documentation comments for public APIs
- Keep functions focused and modular

### Security Guidelines

- **Never** log sensitive data (keys, passwords, plaintext)
- Use constant-time comparison for cryptographic operations
- Validate all inputs at boundaries
- Prefer explicit error handling over `.unwrap()`
- Document security-critical code thoroughly

### Documentation

- All public functions must have doc comments
- Complex algorithms need inline comments explaining the "why"
- Update README.md if changing user-facing behavior
- Add examples for new features

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, etc.
- `security`: Security-related changes

Examples:
```
feat(client): add connection pooling for SOCKS5

fix(server): resolve race condition in ratchet encryption

security(crypto): update to latest X3DH spec

docs: improve installation instructions for ARM routers
```

## Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure all tests pass** (`cargo test --all`)
4. **Format your code** (`cargo fmt`)
5. **Run clippy** and fix warnings (`cargo clippy`)
6. **Update CHANGELOG.md** with your changes
7. **Submit PR** with clear description

### PR Review Process

- All PRs require at least one review
- Address review comments promptly
- Keep PRs focused on a single concern
- Large changes should be discussed in an issue first

## Security Issues

**Do NOT open public issues for security vulnerabilities.**

Instead:

1. Email security@rvpn.org with details
2. Include steps to reproduce
3. Allow time for remediation before public disclosure
4. We follow responsible disclosure practices

We will:
- Acknowledge receipt within 48 hours
- Provide timeline for fix
- Credit you in the security advisory (unless you prefer anonymity)

## Licensing

### Contributor License Agreement

By contributing to R-VPN, you agree that:

1. You have the right to submit the contribution
2. You grant PDG Global Limited a perpetual, worldwide, non-exclusive, royalty-free license to use your contribution under both:
   - AGPL-3.0 (for the open source project)
   - Commercial terms (for dual-licensed distributions)
3. Your contribution is your original work or you have permission to submit it

This dual-licensing approach allows us to:
- Keep R-VPN open source under AGPL
- Offer commercial licenses to businesses
- Protect the project's long-term sustainability

### Copyright Notice

Please include this header in new files:

```rust
// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// Copyright (C) 2024-2025 [Your Name]
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
```

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/creativebastard/rvpn/discussions)
- **Bug reports**: Open an [Issue](https://github.com/creativebastard/rvpn/issues)
- **Security issues**: Email security@rvpn.org
- **Commercial licensing**: Email license@pdg-global.com

Thank you for contributing to R-VPN and helping build genuinely private networking infrastructure!
