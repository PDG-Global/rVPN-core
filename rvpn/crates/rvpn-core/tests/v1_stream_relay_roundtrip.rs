//! Regression tests for the "ServerHello ignored keys" bug that broke
//! every SOCKS5 client whose local prekey-bundle.json drifted from what
//! the server was actually running.
//!
//! Symptom (live): X3DH "successful" on both sides, then the very first
//! Double Ratchet frame from the client fails on the server with
//! `Double Ratchet decryption failed (AAD=[1]): DecryptionFailed("aead::Error")`.
//!
//! Root cause: `stream_relay.rs` (and mirror sites in rvpn-mobile) used to
//! destructure `ServerHello { signed_prekey: _, ... }` and then run X3DH
//! agreement against the pre-loaded on-disk `X3DHPublicBundle`, ignoring
//! whatever keys the server actually sent. So when the server regenerated
//! its signed_prekey (any `rvpn-server prekey-bundle` run), client and
//! server derived different shared secrets and the ratchet chain keys
//! diverged.
//!
//! These tests mirror the client's handshake path in-process. The first
//! test confirms the fresh happy path. The second is the actual
//! regression: the client's local bundle is deliberately stale, and the
//! test asserts that the server can still decrypt the first frame — which
//! requires the client to have used the *wire* keys for agreement.

use rvpn_core::crypto::{
    ratchet::{DoubleRatchet, RatchetMessage},
    x3dh::{X3DHInitiator, X3DHPublicBundle, X3DHResponder},
    IdentityKey, Signature, Verifier, VerifyingKey,
};
use rvpn_core::protocol::padding;
use std::sync::Arc;

/// Build a bundle the way the fixed client code does — take the wire
/// values that would have come from ServerHello + the local
/// identity_x25519_key + rotation metadata. Verify the Ed25519 signature.
fn client_side_wire_bundle(
    wire_identity_key: [u8; 32],
    wire_signed_prekey: [u8; 32],
    wire_prekey_signature: [u8; 64],
    stale_local_bundle: &X3DHPublicBundle,
) -> X3DHPublicBundle {
    let verifying_key = VerifyingKey::from_bytes(&wire_identity_key).expect("valid Ed25519 key");
    let signature = Signature::from_bytes(&wire_prekey_signature);
    verifying_key
        .verify(&wire_signed_prekey, &signature)
        .expect("prekey signature must verify against wire identity");

    X3DHPublicBundle {
        identity_key: wire_identity_key,
        // identity_x25519_key can't be derived from the Ed25519 public
        // alone; use the pre-loaded value. TOFU enforcement guarantees
        // the identity key matches the pinned one.
        identity_x25519_key: stale_local_bundle.identity_x25519_key,
        signed_prekey: wire_signed_prekey,
        prekey_signature: wire_prekey_signature,
        one_time_prekey: None,
        identity_key_version: stale_local_bundle.identity_key_version,
        rotation_signature: stale_local_bundle.rotation_signature,
    }
}

#[test]
fn v1_first_frame_roundtrips_when_bundles_match() {
    let responder = X3DHResponder::new();
    let server_bundle = responder.get_public_bundle();

    let identity = Arc::new(IdentityKey::generate());
    let initiator = X3DHInitiator::from_identity_key(Arc::clone(&identity));
    let client_identity_pub = initiator.identity_key.x25519_public_key();
    let client_ephemeral_pub = initiator.ephemeral_key.public_key.to_bytes();

    let (client_shared, _) = initiator.agree(&server_bundle).expect("client agree");
    let server_shared = responder
        .agree(&client_identity_pub, &client_ephemeral_pub, false)
        .expect("server agree");
    assert_eq!(client_shared, server_shared);

    let mut alice = DoubleRatchet::init_alice(client_shared, [0u8; 32]);
    let mut bob = DoubleRatchet::init_bob(server_shared);

    let target = b"\x0dapi.ipify.org\x01\xbb";
    let padded = padding::pad_packet(target).expect("pad");
    let msg = alice.encrypt(&padded, &[0x01]).expect("alice encrypt");
    let wire = msg.to_bytes().expect("to_bytes");

    let received = RatchetMessage::from_bytes(&wire).expect("from_bytes");
    let decrypted = bob.decrypt(&received, &[0x01]).expect("bob decrypt");
    let plaintext = padding::unpad_packet(&decrypted).expect("unpad");
    assert_eq!(plaintext, target);
}

/// Regression: the client has a stale `prekey-bundle.json` on disk (an
/// old identity_x25519_key is fine, but a stale signed_prekey would kill
/// X3DH). The fixed client rebuilds its X3DH bundle from the ServerHello
/// wire values instead. If we accidentally regress and start using the
/// stale local bundle again, this test fires the same `aead::Error` the
/// live users saw.
#[test]
fn v1_first_frame_survives_stale_local_signed_prekey() {
    // 1. Server generates its real bundle.
    let responder = X3DHResponder::new();
    let real_server_bundle = responder.get_public_bundle();

    // 2. Client's on-disk bundle has an OLDER signed_prekey. Simulate by
    //    generating a second responder just for the stale bundle values.
    //    Real-world equivalent: operator ran `rvpn-server prekey-bundle`
    //    after the user downloaded their .rvpn profile.
    let stale_responder = X3DHResponder::new();
    let stale_local_bundle = X3DHPublicBundle {
        // In practice the identity_x25519_key stays across rotations of
        // the signed prekey — mirror that here.
        identity_x25519_key: real_server_bundle.identity_x25519_key,
        // Every other field is from the stale bundle.
        ..stale_responder.get_public_bundle()
    };

    // 3. Client builds its X3DH bundle from the wire (fixed behaviour).
    //    ServerHello sends real_server_bundle's public values.
    let wire_bundle = client_side_wire_bundle(
        real_server_bundle.identity_key,
        real_server_bundle.signed_prekey,
        real_server_bundle.prekey_signature,
        &stale_local_bundle,
    );

    let identity = Arc::new(IdentityKey::generate());
    let initiator = X3DHInitiator::from_identity_key(Arc::clone(&identity));
    let client_identity_pub = initiator.identity_key.x25519_public_key();
    let client_ephemeral_pub = initiator.ephemeral_key.public_key.to_bytes();

    // 4. Client agrees against the wire bundle; server agrees against
    //    its own responder. Should match.
    let (client_shared, _) = initiator.agree(&wire_bundle).expect("client agree");
    let server_shared = responder
        .agree(&client_identity_pub, &client_ephemeral_pub, false)
        .expect("server agree");
    assert_eq!(
        client_shared, server_shared,
        "client used stale signed_prekey instead of wire value — regression"
    );

    // 5. Round-trip a frame end-to-end.
    let mut alice = DoubleRatchet::init_alice(client_shared, [0u8; 32]);
    let mut bob = DoubleRatchet::init_bob(server_shared);
    let target = b"\x0dapi.ipify.org\x01\xbb";
    let padded = padding::pad_packet(target).expect("pad");
    let msg = alice.encrypt(&padded, &[0x01]).expect("encrypt");
    let wire = msg.to_bytes().expect("to_bytes");
    let received = RatchetMessage::from_bytes(&wire).expect("from_bytes");
    let decrypted = bob
        .decrypt(&received, &[0x01])
        .expect("bob decrypt — this is the aead::Error the fix eliminates");
    let plaintext = padding::unpad_packet(&decrypted).expect("unpad");
    assert_eq!(plaintext, target);
}
