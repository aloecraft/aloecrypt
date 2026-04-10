// tests/pqc.rs

use ml_kem::kem::{Decapsulate, Encapsulate};

use aloecrypt::kem_api::{KyberFullKEM, KyberPublicKEM};
use aloecrypt::signatory_api::{DilithiumSigner, DilithiumVerifier};

use aloecrypt::message_api::*;

use aloecrypt::consts::*;
use aloecrypt::consts_api::*;
use aloecrypt::traits::*;
use chacha20poly1305::Nonce;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::Rng as SysRng;
use rand_chacha::rand_core::SeedableRng;
mod common;
use common::common::test as crosstest;

#[crosstest]
fn load_and_unload_pem() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    let dilithium_signer = DilithiumSigner::new(&mut os_rng);
    let signer_file = dilithium_signer.x_pem(keyfile_password, keyfile_salt, &mut os_rng);
    let loaded_signer =
        DilithiumSigner::x_loads(signer_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let dilithium_verifier: DilithiumVerifier = loaded_signer.into();
    let verifier_file = dilithium_verifier.pem();
    let loaded_verifier = DilithiumVerifier::loads(verifier_file.as_str()).unwrap();

    let dlt_active_from = EMPTY_TIMESTAMP;
    let dlt_expires_at = EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;
    let kyber_full_kem = loaded_signer.create_kyber_kem(
        &mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh,
    );

    let kyber_full_file = kyber_full_kem.x_pem(keyfile_password, keyfile_salt, &mut os_rng);
    let loaded_kyber_full_kem =
        KyberFullKEM::x_loads(kyber_full_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let kyber_public_kem: KyberPublicKEM = loaded_kyber_full_kem.into();
    let kyber_public_file = kyber_public_kem.pem();
    let loaded_kyber_public_kem = KyberPublicKEM::loads(kyber_public_file.as_str()).unwrap();
}

#[crosstest]
fn load_and_unload_builder_bytes() {
    let mut builder_a = aloecrypt::builder_api::SessionBuilder::empty();
    let bytes = builder_a.to_bytes();
    let mut builder_a_loaded = aloecrypt::builder_api::SessionBuilder::from_bytes(bytes);
    assert_eq!(
        builder_a.hash(),
        builder_a_loaded.hash(),
        "loaded hash matches original"
    );
}

#[crosstest]
fn load_and_unload_session_pem() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    // Create two parties and perform a full handshake
    let root_a = DilithiumSigner::new(&mut os_rng);
    let delegate_a =
        root_a.create_dilithium_signer(&mut os_rng, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
    let root_b = DilithiumSigner::new(&mut os_rng);
    let delegate_b =
        root_b.create_dilithium_signer(&mut os_rng, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);

    let mut builder_a =
        aloecrypt::builder_api::SessionBuilder::new(root_b.address(), delegate_a, &mut os_rng);
    let mut builder_b =
        aloecrypt::builder_api::SessionBuilder::new(root_a.address(), delegate_b, &mut os_rng);

    // HELLO → SYN → ACK → SYNACK → WELCOME
    use aloecrypt::session::message::*;
    use aloecrypt::traits::AloecryptAddressable;
    use aloecrypt::traits::AloecryptSessionBuilder;

    let msg_hello = MsgHELLO {
        address: builder_a.address(),
        intro: builder_a.make_party_intro(),
    };
    builder_b
        .on_counterparty_intro(&msg_hello.intro, &mut os_rng)
        .unwrap();

    let msg_syn = MsgSYN {
        syn_to: builder_b.counterparty_intro.unwrap().nonce,
        syn_address: builder_b.address(),
        intro: builder_b.make_party_intro(),
        cipher: builder_b.make_party_cipher().unwrap(),
    };
    builder_a
        .on_counterparty_intro(&msg_syn.intro, &mut os_rng)
        .unwrap();
    builder_a.on_counterparty_cipher(msg_syn.cipher).unwrap();

    let msg_ack = MsgACK {
        ack_to: builder_a.counterparty_intro.unwrap().nonce,
        ack_address: builder_a.counterparty_intro.unwrap().address,
        cipher: builder_a.make_party_cipher().unwrap(),
        challenge: builder_a.make_party_challenge().unwrap(),
    };
    builder_b.on_counterparty_cipher(msg_ack.cipher).unwrap();
    builder_b
        .on_counterparty_challenge(msg_ack.challenge)
        .unwrap();

    let msg_synack = MsgSYNACK {
        syn_ack: builder_b.session_salt.unwrap(),
        challenge: builder_b.make_party_challenge().unwrap(),
        challenge_response: builder_b.make_party_challenge_response().unwrap(),
    };
    builder_a
        .on_counterparty_challenge(msg_synack.challenge)
        .unwrap();
    builder_a
        .on_counterparty_challenge_response(msg_synack.challenge_response)
        .unwrap();

    let msg_welcome = MsgWELCOME {
        challenge_response: builder_a.make_party_challenge_response().unwrap(),
    };
    builder_b
        .on_counterparty_challenge_response(msg_welcome.challenge_response)
        .unwrap();

    let session_a = builder_a.build().unwrap();
    let session_b = builder_b.build().unwrap();

    // Round-trip: encrypt session to PEM, load it back, verify messaging still works
    use aloecrypt::traits::AloecryptHashable;
    let session_a_pem = session_a.x_pem(keyfile_password, keyfile_salt, &mut os_rng);
    let loaded_session_a = aloecrypt::session_api::AloecryptSession::x_loads(
        session_a_pem.as_str(),
        keyfile_password,
        keyfile_salt,
    )
    .unwrap();

    // Verify the loaded session can decrypt messages from B
    let plaintext = b"Hello from B after PEM round-trip!";
    let encrypted = session_b.encrypt(plaintext).unwrap();
    let decrypted = loaded_session_a.decrypt(&encrypted).unwrap();
    assert_eq!(
        decrypted, plaintext,
        "Decryption failed after PEM round-trip"
    );

    // Verify the loaded session can encrypt messages that B can decrypt
    let plaintext_2 = b"Hello from loaded A!";
    let encrypted_2 = loaded_session_a.encrypt(plaintext_2).unwrap();
    let decrypted_2 = session_b.decrypt(&encrypted_2).unwrap();
    assert_eq!(
        decrypted_2, plaintext_2,
        "B failed to decrypt loaded A's message"
    );
}

#[crosstest]
fn session_pem_wrong_password_fails() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";
    let wrong_password = b"Wrong Password!";

    // Minimal session via from_secrets for speed
    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        getrandom::getrandom(&mut buf);
        buf
    }

    let session = aloecrypt::session_api::AloecryptSession::from_secrets(
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SIGNATURE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SESSION_NONCE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::ADDRESS_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SIGNATURE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SESSION_NONCE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::ADDRESS_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SESSION_SALT_SZ }>(),
    );

    let pem = session.x_pem(keyfile_password, keyfile_salt, &mut os_rng);

    // Loading with wrong password should fail
    let result = aloecrypt::session_api::AloecryptSession::x_loads(
        pem.as_str(),
        wrong_password,
        keyfile_salt,
    );
    assert!(result.is_err(), "Loading with wrong password should fail");
}

#[crosstest]
fn session_pem_pub_loads_extracts_counterparty() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        getrandom::getrandom(&mut buf);
        buf
    }

    let address_b: [u8; aloecrypt::consts::ADDRESS_SZ] = rand_bytes();

    let session = aloecrypt::session_api::AloecryptSession::from_secrets(
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SIGNATURE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SESSION_NONCE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::ADDRESS_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SECRET_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SIGNATURE_SZ }>(),
        rand_bytes::<{ aloecrypt::consts::SESSION_NONCE_SZ }>(),
        address_b,
        rand_bytes::<{ aloecrypt::consts::SESSION_SALT_SZ }>(),
    );

    let pem = session.x_pem(keyfile_password, keyfile_salt, &mut os_rng);

    // x_pub_loads should extract the counterparty with zeroed secrets
    let counter_party =
        aloecrypt::session_api::AloecryptSession::x_pub_loads(pem.as_str()).unwrap();
    assert_eq!(
        counter_party.address, address_b,
        "CounterParty address should match"
    );
    assert_eq!(
        counter_party.stable_secret,
        aloecrypt::consts::EMPTY_SECRET,
        "Secrets should be zeroed"
    );
    assert_eq!(
        counter_party.session_secret,
        aloecrypt::consts::EMPTY_SECRET,
        "Secrets should be zeroed"
    );
}

#[crosstest]
fn verify_loaded_pem() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    let dilithium_signer = DilithiumSigner::new(&mut os_rng);
    let signer_file = dilithium_signer.x_pem(keyfile_password, keyfile_salt, &mut os_rng);
    let loaded_signer =
        DilithiumSigner::x_loads(signer_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let dilithium_verifier: DilithiumVerifier = loaded_signer.into();
    let verifier_file = dilithium_verifier.pem();
    let loaded_verifier = DilithiumVerifier::loads(verifier_file.as_str()).unwrap();
    let dlt_active_from = EMPTY_TIMESTAMP;
    let dlt_expires_at = EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;
    let kyber_full_kem = loaded_signer.create_kyber_kem(
        &mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh,
    );

    let kyber_full_file = kyber_full_kem.x_pem(keyfile_password, keyfile_salt, &mut os_rng);
    let loaded_kyber_full_kem =
        KyberFullKEM::x_loads(kyber_full_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let kyber_public_kem: KyberPublicKEM = loaded_kyber_full_kem.into();
    let kyber_public_file = kyber_public_kem.pem();
    let loaded_kyber_public_kem = KyberPublicKEM::loads(kyber_public_file.as_str()).unwrap();

    dilithium_verifier.verify(
        loaded_verifier.signing_material(),
        loaded_verifier.dlt_sig_bytes,
    );
    loaded_verifier.verify(
        dilithium_signer.signing_material(),
        dilithium_signer.dlt_sig_bytes,
    );
    loaded_verifier.verify(
        dilithium_verifier.signing_material(),
        dilithium_verifier.dlt_sig_bytes,
    );
    loaded_verifier.verify(
        loaded_verifier.signing_material(),
        loaded_verifier.dlt_sig_bytes,
    );
    loaded_verifier.verify(
        kyber_full_kem.signing_material(),
        kyber_full_kem.kyb_sig_bytes,
    );
    loaded_verifier.verify(
        kyber_public_kem.signing_material(),
        kyber_public_kem.kyb_sig_bytes,
    );
    loaded_verifier.verify(
        loaded_kyber_full_kem.signing_material(),
        loaded_kyber_full_kem.kyb_sig_bytes,
    );
    loaded_verifier.verify(
        loaded_kyber_public_kem.signing_material(),
        loaded_kyber_public_kem.kyb_sig_bytes,
    );
}
