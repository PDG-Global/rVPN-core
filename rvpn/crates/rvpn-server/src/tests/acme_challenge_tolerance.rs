// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Canary for the rustls-acme challenge-tolerance pin (issue #1).
//
// Before the pin, an authorization listing a challenge type we don't
// implement failed to deserialize — rustls-acme 0.9's ChallengeType is a
// closed enum — and certificate issuance died at startup as soon as the
// CA offered one (Let's Encrypt began offering `dns-persist-01`, which
// also omits the `token` field RFC 8555 only requires for
// http-01/dns-01/tls-alpn-01).
//
// This test pins the behaviour we depend on through the public types, so
// if the `[patch.crates-io]` pin is ever dropped or replaced with an
// unfixed rustls-acme, the suite fails here instead of servers failing in
// the field. The same scenario is covered by regression tests inside the
// fork itself.

#[test]
fn authorization_with_unimplemented_challenge_type_parses() {
    let auth: rustls_acme::acme::Auth = serde_json::from_str(
        r#"{
            "status": "pending",
            "identifier": { "type": "dns", "value": "example.com" },
            "challenges": [
                { "type": "dns-persist-01", "url": "https://ca.example.test/chal/1" },
                { "type": "tls-alpn-01", "url": "https://ca.example.test/chal/2", "token": "tls-token" }
            ]
        }"#,
    )
    .expect("an authorization with an unimplemented, token-less challenge type must parse");
    assert_eq!(auth.challenges.len(), 2);
    assert!(
        auth.challenges
            .iter()
            .any(|c| matches!(c.typ, rustls_acme::acme::ChallengeType::TlsAlpn01)),
        "the supported challenge must still be selectable"
    );
}
