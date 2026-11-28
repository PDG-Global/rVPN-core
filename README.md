# rVPN Core

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

rVPN is a stealth VPN. Traffic between your device and your rVPN server is encrypted with the Double Ratchet and carried over WebSocket/TLS on port 443, so the network in between sees what is designed to look like ordinary HTTPS. The server is the tunnel's exit: it decrypts your traffic and forwards it to its destination, like any VPN server. See [What rVPN protects against](#what-rvpn-protects-against).

This repository contains the core Rust implementation: the client, server, protocol libraries, and mobile FFI bindings. The native macOS, iOS, and Android apps are maintained separately.

## Architecture

- **Double Ratchet Algorithm** (from Signal) for continuous key rotation and forward secrecy
- **X3DH key exchange** for initial handshake without passwords or accounts
- **WebSocket over TLS** transport - designed to look like normal HTTPS on port 443
- **Pooled multiplexing** - many flows share a small set of long-lived connections, with credit-based flow control and TLS session resumption
- **Reverse proxy** - the server hosts a real website on port 443, the VPN endpoint is hidden behind it
- **Decoy site** - the server serves an operator-supplied decoy site from `decoy_root` to plain HTTPS probes, mimicking an nginx static server (Server header, IMF dates, keep-alive), so a prober sees a plausible website instead of a connection that dies after the TLS handshake. Our hosted servers use a provisioning tool (not in this repo) that renders a distinct page per hostname; on a bare install the content is whatever the operator supplies
- **Chrome-like TLS handshake** - the macOS and desktop CLI clients use a Chrome-like TLS 1.3 ClientHello by default (`tls_fingerprint = "chrome"`; `"firefox"` and `"safari"` are accepted but currently behave like `"chrome"`). The iOS and Android apps use rustls with no mimicry (BoringSSL leaks memory inside the iOS Network Extension sandbox)
- **Size padding** - after the handshake, tunnelled packets are padded up to the next 1 KB block, so exact sizes do not show (the X3DH handshake messages themselves are not padded)
- **Stats dashboard** - the CLI serves a live MRTG-style traffic page with a JSON API

## What rVPN protects against

**Protects:** your traffic between your device and your rVPN server. Your ISP, the Wi-Fi operator or a national firewall sees encrypted traffic designed to look like HTTPS to a website on port 443, and a probe of the server gets a decoy site.

**Does not protect from the server operator.** The server decrypts the tunnel to forward your traffic, so whoever runs it can see which destinations you connect to and the content of anything you send without HTTPS (sites you reach over HTTPS stay encrypted between you and the site). Run your own server, or use one run by someone you trust.

**Not claimed:** anonymity, resistance to an observer who can watch both ends, or guaranteed undetectability. Censors adapt; treat stealth as resistance, not a guarantee.

**Logging:** from v1.3.7 the server's default `INFO` level never records client IP addresses, tunnel IPs, destinations or DNS names; those appear only at `debug`/`trace` (`-v`). Earlier versions logged them at `INFO`.

## Why a new protocol instead of WireGuard?

A fair question, and the default instinct is right: WireGuard is about 4,000 lines, kernel-fast, formally analyzed, and has had years of public scrutiny. rVPN is none of those things yet. This section is the honest version of what the design buys and what it costs.

**What threading stealth into the protocol buys**

- **The first bytes on the wire are a browser TLS handshake.** The macOS/desktop clients open with a Chrome-like TLS 1.3 ClientHello (BoringSSL, real ALPN, session resumption). WireGuard's handshake is a fixed-format UDP packet that any DPI labels instantly — so a WireGuard deployment that needs stealth wraps it in a second protocol, and at that point the wrapper *is* the stealth protocol and WireGuard is cargo.
- **TCP/443 in a world that throttles UDP.** WireGuard is UDP-only. Networks that rate-limit UDP or only allow 443/TCP kill it outright.
- **The server answers active probes as a website.** When a censor connects to your server and speaks to it, the same listener serves a real website (the decoy) or completes the tunnel handshake. A layered design can bolt a web server in front, but then two systems must agree about which connections are tunnels — the seam is where probing lives.
- **Pooled flows flatten traffic shape.** Many flows share a small set of long-lived connections with credit-based flow control, and after the handshake packets are padded to 1 KB blocks, so per-flow size and timing patterns don't reach the wire. WireGuard maps flows to packets more or less directly; its sizes and timing are observable unless the transport around it pads.
- **Per-message key rotation.** Both protocols have forward secrecy: WireGuard rekeys with a fresh ephemeral handshake about every two minutes, so a stolen session key exposes minutes of traffic, and a later identity-key theft does not decrypt recordings. The Double Ratchet adds per-message rotation and, once DH steps run regularly (a fix is pending in our tracker), recovery from a session-state compromise within one round trip rather than at the next rekey. Neither protocol protects against a stolen long-term identity key — that means rotating it out of band in both.

**What it costs**

- WireGuard's crypto is analyzed; ours is young. "Don't roll your own protocol" is correct advice for most projects, and we are paying the price of the exception: this codebase needs, and is getting, outside review rather than inherited confidence.
- Wrapping WireGuard in an obfuscation transport (the udp2raw / pluggable-transport pattern) is a legitimate design: you keep the analyzed crypto and swap the wire format. What it can't do is shape the handshake or the probe surface, because the obfuscator sits outside the protocol that generates them.

**Which to run**

- If your adversary is a passive classifier and you control both ends, WireGuard plus a pluggable transport is simpler and better analyzed.
- If your adversary actively probes servers or throttles UDP, the integrated design is what those two properties require. That is the adversary rVPN is built for.

Neither choice is a guarantee. Censors adapt; treat stealth as resistance, not invisibility.

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

## Upgrading to protocol v2

rVPN's handshake upgraded to **ratchet v2** (header-authenticating AAD with
commit-after-verify). Compatibility is negotiated during the handshake:

- A **v2-capable client refuses a v1 server**, by design — otherwise an
  attacker could strip the v2 capability and silently downgrade your
  connection. The client fails with
  `server does not speak ratchet v2; a v2-capable client refuses v1`.
- A **v2-capable server accepts v1 clients until 2027-02-01** (a sunset
  coded into the software), so upgrading the server first locks nobody out.

**Upgrade order: server first, then clients.**
See [docs/version-compatibility.md](docs/version-compatibility.md) for the
full compatibility matrix.

## Building

Requires Rust 1.88+.

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

The native app source code (Swift and Kotlin) is not included in this repository.

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

rVPN is dual-licensed:

- **AGPL-3.0-or-later** for open-source use
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
