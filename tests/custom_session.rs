// tests/custom_session.rs
//
// Tests for AloecryptSession::from_secrets — verifying that the double-KEM
// encryption layer can be used independently of the handshake protocol.

use aloecrypt::consts::*;
use aloecrypt::session::session::AloecryptSession;
use aloecrypt::traits::AloecryptAddressable;

mod common;
use common::common::test as crosstest;

/// Generate a random secret of the given array size.
fn random_secret<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf);
    buf
}

/// Build a symmetric pair of sessions from the same shared secrets,
/// swapping the party/counterparty roles between A and B.
fn make_session_pair() -> (AloecryptSession, AloecryptSession) {
    let stable_secret_a: [u8; SECRET_SZ] = random_secret();
    let session_secret_a: [u8; SECRET_SZ] = random_secret();
    let stable_secret_b: [u8; SECRET_SZ] = random_secret();
    let session_secret_b: [u8; SECRET_SZ] = random_secret();

    let signature_a: [u8; SIGNATURE_SZ] = random_secret();
    let signature_b: [u8; SIGNATURE_SZ] = random_secret();

    let nonce_a: [u8; SESSION_NONCE_SZ] = random_secret();
    let nonce_b: [u8; SESSION_NONCE_SZ] = random_secret();

    let address_a: [u8; ADDRESS_SZ] = random_secret();
    let address_b: [u8; ADDRESS_SZ] = random_secret();

    let session_salt: [u8; SESSION_SALT_SZ] = random_secret();

    let session_a = AloecryptSession::from_secrets(
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        session_salt,
    );

    let session_b = AloecryptSession::from_secrets(
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        session_salt,
    );

    (session_a, session_b)
}

#[crosstest]
fn test_custom_session_bidirectional_messaging() {
    let (session_a, session_b) = make_session_pair();

    // A → B
    let plaintext_a = b"hello from custom session a";
    let encrypted_a = session_a.encrypt(plaintext_a).expect("A encrypt failed");
    let decrypted_a = session_b.decrypt(&encrypted_a).expect("B decrypt failed");
    assert_eq!(decrypted_a, plaintext_a, "A→B message mismatch");

    // B → A
    let plaintext_b = b"hello back from custom session b";
    let encrypted_b = session_b.encrypt(plaintext_b).expect("B encrypt failed");
    let decrypted_b = session_a.decrypt(&encrypted_b).expect("A decrypt failed");
    assert_eq!(decrypted_b, plaintext_b, "B→A message mismatch");
}

#[crosstest]
fn test_custom_session_wrong_secrets_fail_decryption() {
    let (session_a, _) = make_session_pair();

    // Build a second session with completely different secrets —
    // decryption of A's message should fail or produce garbage.
    let (_, session_c) = make_session_pair();

    let plaintext = b"this should not decrypt correctly";
    let encrypted = session_a.encrypt(plaintext).expect("encrypt failed");
    let result = session_c.decrypt(&encrypted);

    assert!(
        result.is_err(),
        "Decryption with wrong secrets should fail, got {:?}",
        result
    );
}

#[crosstest]
fn test_custom_session_salt_is_significant() {
    // Two session pairs with identical secrets but different salts
    // should produce different ciphertexts.
    let stable_secret_a: [u8; SECRET_SZ] = random_secret();
    let session_secret_a: [u8; SECRET_SZ] = random_secret();
    let stable_secret_b: [u8; SECRET_SZ] = random_secret();
    let session_secret_b: [u8; SECRET_SZ] = random_secret();
    let signature_a: [u8; SIGNATURE_SZ] = random_secret();
    let signature_b: [u8; SIGNATURE_SZ] = random_secret();
    let nonce_a: [u8; SESSION_NONCE_SZ] = random_secret();
    let nonce_b: [u8; SESSION_NONCE_SZ] = random_secret();
    let address_a: [u8; ADDRESS_SZ] = random_secret();
    let address_b: [u8; ADDRESS_SZ] = random_secret();

    let salt_1: [u8; SESSION_SALT_SZ] = random_secret();
    let mut salt_2 = salt_1;
    salt_2[0] ^= 0xff; // flip one byte

    let session_1 = AloecryptSession::from_secrets(
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        salt_1,
    );

    let session_2 = AloecryptSession::from_secrets(
        stable_secret_a,
        session_secret_a,
        signature_a,
        nonce_a,
        address_a,
        stable_secret_b,
        session_secret_b,
        signature_b,
        nonce_b,
        address_b,
        salt_2,
    );

    let plaintext = b"same plaintext, different salt";
    let ct1 = session_1.encrypt(plaintext).expect("encrypt 1 failed");
    let ct2 = session_2.encrypt(plaintext).expect("encrypt 2 failed");

    assert_ne!(
        ct1, ct2,
        "Different salts should produce different ciphertexts"
    );
}

// #[crosstest]
#[test]
fn test_custom_session_empty_plaintext() {
    let (session_a, session_b) = make_session_pair();

    let plaintext = b"";
    let encrypted = session_a.encrypt(plaintext).expect("encrypt failed");
    let decrypted = session_b.decrypt(&encrypted).expect("decrypt failed");

    let session_a_address = session_a.address();
    let session_b_address = session_b.address();
    let session_a_delegate_address = session_a.party.delegate_signer.address();
    let session_b_delegate_address = session_b.party.delegate_signer.address();
    let session_a_counter_party_address = session_a.counter_party.address();
    let session_b_counter_party_address = session_b.counter_party.address();
    let session_a_counter_party_verifier_address = session_a.counter_party.verifier.address();
    let session_b_counter_party_verifier_address = session_b.counter_party.verifier.address();

    assert_eq!(decrypted, plaintext);
}

#[crosstest]
fn test_custom_session_large_plaintext() {
    let (session_a, session_b) = make_session_pair();

    let plaintext = vec![0xabu8; 1024 * 1024]; // 1MB
    let encrypted = session_a.encrypt(&plaintext).expect("encrypt failed");
    let decrypted = session_b.decrypt(&encrypted).expect("decrypt failed");
    assert_eq!(decrypted, plaintext);
}
