// tests/session_handshake.rs

use aloecrypt::consts::*;
use aloecrypt::error::AloecryptSessionError;
use aloecrypt::kem::{KyberFullKEM, KyberPublicKEM};
use aloecrypt::session::builder::SessionBuilder;
use aloecrypt::session::message::{MsgACK, MsgHELLO, MsgSYN, MsgSYNACK, MsgWELCOME};
use aloecrypt::signatory::{DilithiumSigner, DilithiumVerifier};
use aloecrypt::traits::{
    AloecryptDecapsulator, AloecryptEncapsulator, AloecryptPEM, AloecryptPasswordPEM,
    AloecryptSignable, AloecryptSigner, AloecryptVerifier,
};
use rand_core::OsRng;

#[derive(Clone)]
struct TestParty {
    root_signer: DilithiumSigner,
    delegate_signer: DilithiumSigner,
    root_kem: KyberFullKEM,
    msg_kem: KyberFullKEM,
    secure_session: Option<SessionBuilder>,
}

mod common;
use common::common::test as crosstest;

impl TestParty {
    fn new() -> Self {
        let mut os_rng = OsRng;
        let root_signer = DilithiumSigner::new(&mut os_rng);
        let root_kem = root_signer.canonical_kyber_kem(
            &[0u8],
            EMPTY_TIMESTAMP,
            EMPTY_TIMESTAMP,
            0,
            0,
        );
        let delegate_signer =
            root_signer.create_dilithium_signer(&mut os_rng, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
        let msg_kem = delegate_signer.canonical_kyber_kem(
            &[0u8],
            EMPTY_TIMESTAMP,
            EMPTY_TIMESTAMP,
            0,
            0,
        );
        Self {
            root_signer,
            delegate_signer,
            root_kem,
            msg_kem,
            secure_session: None,
        }
    }

    fn address(&self) -> [u8; ADDRESS_SZ] {
        self.root_signer.dlt_address
    }

    fn start_session(&mut self, counterparty_address: [u8; ADDRESS_SZ]) {
        self.secure_session = Some(SessionBuilder::new(counterparty_address, self.delegate_signer));
    }
}

/// Performs a full HELLO → SYN → ACK → SYNACK → WELCOME handshake between
/// two parties and returns their built sessions.
fn perform_handshake(
    session_a: &mut SessionBuilder,
    session_b: &mut SessionBuilder,
) -> Result<(), AloecryptSessionError> {
    // A → B: HELLO
    let msg_hello = MsgHELLO {
        address: session_a.address(),
        intro: session_a.make_party_intro(),
    };
    session_b.on_counterparty_intro(&msg_hello.intro)?;

    // B → A: SYN
    let msg_syn = MsgSYN {
        intro: session_b.make_party_intro(),
        cipher: session_b.make_party_cipher().unwrap(),
    };
    session_a.on_counterparty_intro(&msg_syn.intro)?;
    session_a.on_counterparty_cipher(msg_syn.cipher)?;

    // A → B: ACK
    let msg_ack = MsgACK {
        cipher: session_a.make_party_cipher().unwrap(),
        challenge: session_a.make_party_challenge().unwrap(),
    };
    session_b.on_counterparty_cipher(msg_ack.cipher)?;
    session_b.on_counterparty_challenge(msg_ack.challenge)?;

    // B → A: SYNACK
    let msg_synack = MsgSYNACK {
        challenge: session_b.make_party_challenge().unwrap(),
        challenge_response: session_b.make_party_challenge_response().unwrap(),
    };
    session_a.on_counterparty_challenge(msg_synack.challenge)?;
    session_a.on_counterparty_challenge_response(msg_synack.challenge_response)?;

    // A → B: WELCOME
    let msg_welcome = MsgWELCOME {
        challenge_response: session_a.make_party_challenge_response().unwrap(),
    };
    session_b.on_counterparty_challenge_response(msg_welcome.challenge_response)?;

    Ok(())
}

#[crosstest]
fn test_full_handshake_and_bidirectional_messaging() {
    let mut party_a = TestParty::new();
    let mut party_b = TestParty::new();

    party_a.start_session(party_b.address());
    party_b.start_session(party_a.address());

    let (mut session_a, mut session_b) = match (party_a.secure_session, party_b.secure_session) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("Sessions should be initialised"),
    };

    perform_handshake(&mut session_a, &mut session_b)
        .expect("Handshake should complete without error");

    let built_a = session_a.build().expect("Session A should build");
    let built_b = session_b.build().expect("Session B should build");

    // A → B
    let plaintext_a = b"Hello from Party A!";
    let encrypted_a = built_a.encrypt(plaintext_a).expect("A encrypt failed");
    let decrypted_a = built_b.decrypt(&encrypted_a).expect("B decrypt failed");
    assert_eq!(decrypted_a, plaintext_a, "A→B message mismatch");

    // B → A
    let plaintext_b = b"Hello back from Party B!";
    let encrypted_b = built_b.encrypt(plaintext_b).expect("B encrypt failed");
    let decrypted_b = built_a.decrypt(&encrypted_b).expect("A decrypt failed");
    assert_eq!(decrypted_b, plaintext_b, "B→A message mismatch");
}

#[crosstest]
fn test_handshake_intro_step_is_required_before_cipher() {
    let mut party_a = TestParty::new();
    let mut party_b = TestParty::new();

    party_a.start_session(party_b.address());
    party_b.start_session(party_a.address());

    let (mut session_a, mut session_b) = match (party_a.secure_session, party_b.secure_session) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("Sessions should be initialised"),
    };

    // session_b has not received an intro from A yet, so make_party_cipher should fail
    let result = session_b.make_party_cipher();
    assert!(
        matches!(result, Err(AloecryptSessionError::NoCounterPartyINTRO)),
        "Expected NoCounterPartyINTRO when cipher is made before intro, got {:?}",
        result
    );
}

#[crosstest]
fn test_wrong_challenge_response_is_rejected() {
    use aloecrypt::session::builder::PartyRESPONSE;
    let mut party_a = TestParty::new();
    let mut party_b = TestParty::new();

    party_a.start_session(party_b.address());
    party_b.start_session(party_a.address());

    let (mut session_a, mut session_b) = match (party_a.secure_session, party_b.secure_session) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("Sessions should be initialised"),
    };

    // Run handshake up to the point where B expects A's challenge response
    let msg_hello = MsgHELLO {
        address: session_a.address(),
        intro: session_a.make_party_intro(),
    };
    session_b.on_counterparty_intro(&msg_hello.intro).unwrap();

    let msg_syn = MsgSYN {
        intro: session_b.make_party_intro(),
        cipher: session_b.make_party_cipher().unwrap(),
    };
    session_a.on_counterparty_intro(&msg_syn.intro).unwrap();
    session_a.on_counterparty_cipher(msg_syn.cipher).unwrap();

    let msg_ack = MsgACK {
        cipher: session_a.make_party_cipher().unwrap(),
        challenge: session_a.make_party_challenge().unwrap(),
    };
    session_b.on_counterparty_cipher(msg_ack.cipher).unwrap();
    session_b.on_counterparty_challenge(msg_ack.challenge).unwrap();

    let msg_synack = MsgSYNACK {
        challenge: session_b.make_party_challenge().unwrap(),
        challenge_response: session_b.make_party_challenge_response().unwrap(),
    };
    session_a.on_counterparty_challenge(msg_synack.challenge).unwrap();
    session_a.on_counterparty_challenge_response(msg_synack.challenge_response).unwrap();

    // Send a fabricated (all-zeros) challenge response instead of the real one
    let fake_response = [0u8; SESSION_NONCE_SZ];

    let result = session_b.on_counterparty_challenge_response(PartyRESPONSE { decrypted_challenge: fake_response });
    assert!(
        matches!(result, Err(AloecryptSessionError::CounterPartyChallengeMismatch)),
        "Expected CounterPartyChallengeMismatch, got {:?}",
        result
    );
}