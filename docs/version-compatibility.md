# Client–server version compatibility (ratchet v1/v2)

rVPN upgraded its handshake to **ratchet v2** (header-authenticating AAD with
commit-after-verify). The upgrade is negotiated during the X3DH handshake, so
old and new software can coexist — within a defined window.

## The matrix

| Client \ Server | v1 server (≤ v1.3.9) | v2-capable server (upcoming release) |
|---|---|---|
| **v1 client** (all released apps today) | ✅ works | ✅ works **until 1 Feb 2027** (coded sunset) |
| **v2 client** (upcoming releases) | ❌ refuses to connect | ✅ works (v2 negotiated) |

## Why v2 clients refuse v1 servers

A v2-capable client deliberately refuses to fall back to the v1 handshake.
Without that hard floor, an attacker between you and the server could strip
the v2 capability advertisement and silently force the weaker v1 protocol.
Refusing the connection is the failure you want: it is loud, and it cannot
be exploited as a downgrade.

## What this means for you

**Using the official servers:** nothing to do. The servers are upgraded
first; your current app keeps working throughout. When the v2-capable app
update reaches you, everything continues working — just with the stronger
handshake. The transition is seamless.

**Self-hosting a server:** upgrade your server **before** updating the
clients on your devices. A v2 client cannot connect to a v1 server (by
design, see above). The v2-capable server accepts both, so upgrading the
server first never locks anyone out.

**The deadline:** on **1 February 2027** v2-capable servers stop accepting
v1 clients (the sunset is coded into the software). Make sure your apps are
updated to a v2-capable release before that date.

## Version guide

- **v1 wire:** server releases up to and including **v1.3.9**; all mobile
  and desktop app releases shipped to date.
- **v2 wire:** negotiated when both sides advertise `CAP_RATCHET_V2`. The
  negotiation logic and sunset are in
  [`rvpn/crates/rvpn-core/src/crypto/x3dh.rs`](../rvpn/crates/rvpn-core/src/crypto/x3dh.rs)
  (`negotiate_version`, `V1_SUNSET_UNIX`).
