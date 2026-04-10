// tests/session_handshake.rs
//
// These structs are large (~20KB+ each in debug mode) so we override the
// default test-harness thread stack to 32 MB.  The #[test] attribute still
// works; only the runner thread size changes.

#[cfg(test)]
mod harness {
    pub const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB
}

use aloecrypt::builder_api::SessionBuilder;
use aloecrypt::consts::*;
use aloecrypt::error::AloecryptSessionError;
use aloecrypt::kem_api::{KyberFullKEM, KyberPublicKEM};
use aloecrypt::message_api::{MsgACK, MsgHELLO, MsgSYN, MsgSYNACK, MsgWELCOME};
use aloecrypt::party_api::*;
use aloecrypt::signatory_api::{DilithiumSigner, DilithiumVerifier};
use aloecrypt::traits::*;
use aloecrypt::types::DilithiumSignature;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::Rng as SysRng;
use rand_chacha::rand_core::SeedableRng;

#[derive(Clone)]
struct TestParty {
    root_signer: DilithiumSigner,
    delegate_signer: DilithiumSigner,
    root_kem: KyberFullKEM,
    msg_kem: KyberFullKEM,
    secure_session: Option<SessionBuilder>,
}

mod common;
use common::common::print_stack_remaining;
use common::common::test as crosstest;

impl TestParty {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        println!("[TestParty::new <1> !!!!]");
        print_stack_remaining();
        getrandom::getrandom(&mut seed);
        let mut os_rng = ChaCha20Rng::from_seed(seed);
        println!("[TestParty::new <2> !!!!??]");
        print_stack_remaining();
        let root_signer = DilithiumSigner::new(&mut os_rng);
        println!("[TestParty::new <3> !!!!]");
        print_stack_remaining();
        let root_kem =
            root_signer.canonical_kyber_kem(&[0u8], EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
        println!("[TestParty::new <4> !!!!]");
        print_stack_remaining();
        let delegate_signer = root_signer.create_dilithium_signer(
            &mut os_rng,
            EMPTY_TIMESTAMP,
            EMPTY_TIMESTAMP,
            0,
            0,
        );
        println!("[TestParty::new <5> !!!!]");
        print_stack_remaining();
        let msg_kem =
            delegate_signer.canonical_kyber_kem(&[0u8], EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
        println!("[TestParty::new <7> !!!!]");
        print_stack_remaining();
        Self {
            root_signer,
            delegate_signer,
            root_kem,
            msg_kem,
            secure_session: None,
        }
    }

    fn address(&self) -> [u8; ADDRESS_SZ] {
        self.root_signer.address()
    }

    fn start_session(&mut self, counterparty_address: [u8; ADDRESS_SZ]) {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed);
        let mut os_rng = ChaCha20Rng::from_seed(seed);
        self.secure_session = Some(SessionBuilder::new(
            counterparty_address,
            self.delegate_signer,
            &mut os_rng,
        ));
    }
}

/// Performs a full HELLO → SYN → ACK → SYNACK → WELCOME handshake between
/// two parties and returns their built sessions.
fn perform_handshake(
    session_a: &mut SessionBuilder,
    session_b: &mut SessionBuilder,
) -> Result<(), AloecryptSessionError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);
    // A → B: HELLO
    let msg_hello = MsgHELLO {
        address: session_a.address(),
        intro: session_a.make_party_intro(),
    };
    session_b.on_counterparty_intro(&msg_hello.intro, &mut os_rng)?;

    // B → A: SYN
    let msg_syn = MsgSYN {
        syn_to: session_b.counterparty_intro.unwrap().nonce,
        syn_address: session_b.address(),
        intro: session_b.make_party_intro(),
        cipher: session_b.make_party_cipher().unwrap(),
    };
    session_a.on_counterparty_intro(&msg_syn.intro, &mut os_rng)?;
    session_a.on_counterparty_cipher(msg_syn.cipher)?;

    // A → B: ACK
    let msg_ack = MsgACK {
        ack_to: session_a.counterparty_intro.unwrap().nonce,
        ack_address: session_a.counterparty_intro.unwrap().address,
        cipher: session_a.make_party_cipher().unwrap(),
        challenge: session_a.make_party_challenge().unwrap(),
    };
    session_b.on_counterparty_cipher(msg_ack.cipher)?;
    session_b.on_counterparty_challenge(msg_ack.challenge)?;

    // B → A: SYNACK
    let msg_synack = MsgSYNACK {
        syn_ack: session_b.session_salt.unwrap(),
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

// }

// fn _impl_test_full_handshake_and_bidirectional_messaging() {
#[crosstest]
fn test_1() {
    println!("START test_full_handshake_and_bidirectional_messaging");
    // fn test_full_handshake_and_bidirectional_messaging() {
    println!("[00 !!!!]");
    // print_stack_remaining();
    // println!("[A !!!!]");
    let mut party_a = TestParty::new();
    // println!("[B !!!!]");
    let mut party_b = TestParty::new();
    // println!("[C !!!!]");
    // print_stack_remaining();

    println!("TestParty size: {}", std::mem::size_of::<TestParty>());
    println!(
        "DilithiumSigner size: {}",
        std::mem::size_of::<DilithiumSigner>()
    );
    println!(
        "DilithiumVerifier size: {}",
        std::mem::size_of::<DilithiumVerifier>()
    );
    println!("KyberFullKEM size: {}", std::mem::size_of::<KyberFullKEM>());
    println!(
        "KyberPublicKEM size: {}",
        std::mem::size_of::<KyberPublicKEM>()
    );
    println!(
        "DilithiumSignature size: {}",
        std::mem::size_of::<DilithiumSignature>()
    );
    println!("Party size: {}", std::mem::size_of::<Party>());
    println!("CounterParty size: {}", std::mem::size_of::<CounterParty>());
    println!(
        "SessionBuilder size: {}",
        std::mem::size_of::<SessionBuilder>()
    );

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

    println!("END test_full_handshake_and_bidirectional_messaging");
}

// #[crosstest]
#[test]
fn test_handshake_intro_step_is_required_before_cipher() {
    _impl_test_handshake_intro_step_is_required_before_cipher();
}
fn _impl_test_handshake_intro_step_is_required_before_cipher() {
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

// #[crosstest]
#[test]
fn test_handshake_via_message_pems() {
    println!("impl_test_handshake_via_message_pems");
    println!("=================================");
    println!("[00 !!!!]");
    print_stack_remaining();

    println!("[01 !!!!]");
    print_stack_remaining();

    println!("[02 !!!!]");
    print_stack_remaining();
    let mut party_a = TestParty::new();
    println!("[03 !!!!]");
    print_stack_remaining();
    let mut party_b = TestParty::new();

    println!("[04 !!!!]");
    print_stack_remaining();
    party_a.start_session(party_b.address());

    println!("[05 !!!!]");
    print_stack_remaining();
    party_b.start_session(party_a.address());

    println!("[06 !!!!]");
    print_stack_remaining();

    let (mut session_a, mut session_b) = match (party_a.secure_session, party_b.secure_session) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("Sessions should be initialised"),
    };

    println!("[07 !!!!]");
    print_stack_remaining();

    // A → B: HELLO (serialize to PEM, deserialize, then process)
    let msg_hello = MsgHELLO {
        address: session_a.address(),
        intro: session_a.make_party_intro(),
    };
    let hello_pem = msg_hello.pem();
    let msg_hello_loaded = MsgHELLO::loads(hello_pem.as_str()).unwrap();

    use aloecrypt::traits::AloecryptPEM;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);
    session_b
        .on_counterparty_intro(&msg_hello_loaded.intro, &mut os_rng)
        .unwrap();

    // B → A: SYN
    let msg_syn = MsgSYN {
        syn_to: session_b.counterparty_intro.unwrap().nonce,
        syn_address: session_b.address(),
        intro: session_b.make_party_intro(),
        cipher: session_b.make_party_cipher().unwrap(),
    };
    let syn_pem = msg_syn.pem();
    let msg_syn_loaded = MsgSYN::loads(syn_pem.as_str()).unwrap();
    session_a
        .on_counterparty_intro(&msg_syn_loaded.intro, &mut os_rng)
        .unwrap();
    session_a
        .on_counterparty_cipher(msg_syn_loaded.cipher)
        .unwrap();

    // A → B: ACK
    let msg_ack = MsgACK {
        ack_to: session_a.counterparty_intro.unwrap().nonce,
        ack_address: session_a.counterparty_intro.unwrap().address,
        cipher: session_a.make_party_cipher().unwrap(),
        challenge: session_a.make_party_challenge().unwrap(),
    };
    let ack_pem = msg_ack.pem();
    let msg_ack_loaded = MsgACK::loads(ack_pem.as_str()).unwrap();
    session_b
        .on_counterparty_cipher(msg_ack_loaded.cipher)
        .unwrap();
    session_b
        .on_counterparty_challenge(msg_ack_loaded.challenge)
        .unwrap();

    // B → A: SYNACK
    let msg_synack = MsgSYNACK {
        syn_ack: session_b.session_salt.unwrap(),
        challenge: session_b.make_party_challenge().unwrap(),
        challenge_response: session_b.make_party_challenge_response().unwrap(),
    };
    let synack_pem = msg_synack.pem();
    let msg_synack_loaded = MsgSYNACK::loads(synack_pem.as_str()).unwrap();
    session_a
        .on_counterparty_challenge(msg_synack_loaded.challenge)
        .unwrap();
    session_a
        .on_counterparty_challenge_response(msg_synack_loaded.challenge_response)
        .unwrap();

    // A → B: WELCOME
    let msg_welcome = MsgWELCOME {
        challenge_response: session_a.make_party_challenge_response().unwrap(),
    };
    let welcome_pem = msg_welcome.pem();
    let msg_welcome_loaded = MsgWELCOME::loads(welcome_pem.as_str()).unwrap();
    session_b
        .on_counterparty_challenge_response(msg_welcome_loaded.challenge_response)
        .unwrap();

    // Build sessions and verify bidirectional messaging
    let built_a = session_a.build().expect("Session A should build");
    let built_b = session_b.build().expect("Session B should build");

    let plaintext_a = b"Hello from A via PEM handshake!";
    let encrypted_a = built_a.encrypt(plaintext_a).expect("A encrypt failed");
    let decrypted_a = built_b.decrypt(&encrypted_a).expect("B decrypt failed");
    assert_eq!(
        decrypted_a, plaintext_a,
        "A->B message mismatch after PEM handshake"
    );

    let plaintext_b = b"Hello back from B via PEM handshake!";
    let encrypted_b = built_b.encrypt(plaintext_b).expect("B encrypt failed");
    let decrypted_b = built_a.decrypt(&encrypted_b).expect("A decrypt failed");
    assert_eq!(
        decrypted_b, plaintext_b,
        "B->A message mismatch after PEM handshake"
    );
}

#[crosstest]
fn test_wrong_challenge_response_is_rejected() {
    // std::thread::Builder::new()
    //     .stack_size(harness::STACK_SIZE)
    //     .spawn(|| _impl_test_wrong_challenge_response_is_rejected())
    //     .unwrap()
    //     .join()
    //     .unwrap();
    _impl_test_wrong_challenge_response_is_rejected()
}
fn _impl_test_wrong_challenge_response_is_rejected() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    let mut os_rng = ChaCha20Rng::from_seed(seed);

    use aloecrypt::builder_api::PartyRESPONSE;
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
    session_b
        .on_counterparty_intro(&msg_hello.intro, &mut os_rng)
        .unwrap();

    let msg_syn = MsgSYN {
        syn_to: session_b.counterparty_intro.unwrap().nonce,
        syn_address: session_b.address(),
        intro: session_b.make_party_intro(),
        cipher: session_b.make_party_cipher().unwrap(),
    };
    session_a
        .on_counterparty_intro(&msg_syn.intro, &mut os_rng)
        .unwrap();
    session_a.on_counterparty_cipher(msg_syn.cipher).unwrap();

    let msg_ack = MsgACK {
        ack_to: session_a.counterparty_intro.unwrap().nonce,
        ack_address: session_a.counterparty_intro.unwrap().address,
        cipher: session_a.make_party_cipher().unwrap(),
        challenge: session_a.make_party_challenge().unwrap(),
    };
    session_b.on_counterparty_cipher(msg_ack.cipher).unwrap();
    session_b
        .on_counterparty_challenge(msg_ack.challenge)
        .unwrap();

    let msg_synack = MsgSYNACK {
        syn_ack: session_b.session_salt.unwrap(),
        challenge: session_b.make_party_challenge().unwrap(),
        challenge_response: session_b.make_party_challenge_response().unwrap(),
    };
    session_a
        .on_counterparty_challenge(msg_synack.challenge)
        .unwrap();
    session_a
        .on_counterparty_challenge_response(msg_synack.challenge_response)
        .unwrap();

    // Send a fabricated (all-zeros) challenge response instead of the real one
    let fake_response = [0u8; SESSION_NONCE_SZ];

    let result = session_b.on_counterparty_challenge_response(PartyRESPONSE {
        decrypted_challenge: fake_response,
    });
    assert!(
        matches!(
            result,
            Err(AloecryptSessionError::CounterPartyChallengeMismatch)
        ),
        "Expected CounterPartyChallengeMismatch, got {:?}",
        result
    );
}
