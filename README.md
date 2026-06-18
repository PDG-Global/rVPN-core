# rVPN Core

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

R-VPN is a stealth VPN with end-to-end encryption. The relay server forwards encrypted packets but cannot read them.

This repository contains the core Rust implementation: the client, server, protocol libraries, and mobile FFI bindings. The native macOS, iOS, and Android apps are maintained separately.

## Architecture

- **Double Ratchet Algorithm** (from Signal) for continuous key rotation and forward secrecy
- **X3DH key exchange** for initial handshake without passwords or accounts
- **WebSocket over TLS** transport - traffic is indistinguishable from normal HTTPS
- **Reverse proxy** - the server hosts a real website on port 443, the VPN endpoint is hidden behind it
- **TLS fingerprint mimicry** - connections mimic Chrome, Firefox, or Safari fingerprints

## Repository Structure

```
rvpn/
  Cargo.toml         Workspace manifest
  Cargo.lock         Dependency lockfile
  crates/
    rvpn-core/       Protocol, cryptography, packet handling
    rvpn-client/     CLI client binary (SOCKS5 and TUN modes)
    rvpn-server/     Server binary (relay, NAT, TUN)
    rvpn-mobile/     FFI bindings for iOS/macOS/Android
```

## Building

Requires Rust 1.75+.

```bash
cd rvpn

# Build everything
cargo build --release

# Build specific package
cargo build --release --package rvpn-client
cargo build --release --package rvpn-server
cargo build --release --package rvpn-mobile

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

### Cross-compilation

Install [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and [zig](https://ziglang.org/):

```bash
# macOS (Apple Silicon)
cargo zigbuild --release --target aarch64-apple-darwin

# macOS (Intel)
cargo zigbuild --release --target x86_64-apple-darwin

# Linux x86_64
cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Linux ARMv7
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf

# Linux musl (static)
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

### Mobile library

The `rvpn-mobile` crate produces a static library (`librvpn_mobile.a`) for linking into native iOS, macOS, and Android apps. Build it with the appropriate feature flag:

```bash
# iOS
cargo build --release --package rvpn-mobile --target aarch64-apple-ios --features ios-direct-tun

# macOS
cargo build --release --package rvpn-mobile --target aarch64-apple-darwin --features macos-direct-tun

# Android
cargo build --release --package rvpn-mobile --target aarch64-linux-android --features android-direct-tun
```

The native app source code (Swift, Kotlin/Flutter) is not included in this repository.

## Usage

### Generate keys

```bash
# Server identity key
cargo run --release --package rvpn-server -- keygen

# Server prekey bundle
cargo run --release --package rvpn-server -- prekey-bundle \
  --identity server_identity.key \
  --output prekey-bundle.json

# Client identity key
cargo run --release --package rvpn-client -- keygen --output identity.key
```

### Run the server

```bash
cargo run --release --package rvpn-server -- --config server.toml
```

### Run the client (SOCKS5 proxy mode)

```bash
cargo run --release --package rvpn-client -- --config client.toml
```

This starts a SOCKS5 proxy on `127.0.0.1:1080`. Configure your browser or system to use it.

### Run the client (TUN mode, requires root)

```bash
sudo cargo run --release --package rvpn-client -- --config client.toml --tun
```

## Releases

Pre-built binaries for all platforms are published as GitHub releases on this repository. The native apps (macOS, iOS, Android) are distributed through their respective app stores.

## Documentation

Full documentation is at [docs.rvpn.org](https://docs.rvpn.org). The whitepaper is at [rvpn.org](https://rvpn.org).

## Licensing

R-VPN is dual-licensed:

- **AGPL-3.0** for open-source use
- **Commercial license** for proprietary use, SaaS providers, or when AGPL obligations cannot be met

See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

Commercial licensing: license@pdg-global.com

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately to security@rvpn.org. See [SECURITY.md](SECURITY.md).

## About

PDG Global Limited (Hong Kong)

- Website: https://rvpn.org
- GitHub: https://github.com/PDG-Global/rVPN-core
