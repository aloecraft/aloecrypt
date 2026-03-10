use ml_kem::kem::{Decapsulate, Encapsulate};

use rand_core::{OsRng, RngCore};
use aloecrypt::error::AloecryptSessionError;
use aloecrypt::signatory::{DilithiumSigner,DilithiumVerifier};
use aloecrypt::kem::{KyberFullKEM, KyberPublicKEM};
use aloecrypt::consts::*;
use aloecrypt::session::builder::SessionBuilder;
use aloecrypt::session::message::{MsgHELLO, MsgSYN, MsgACK, MsgSYNACK, MsgWELCOME};
use aloecrypt::traits::{AloecryptDecapsulator, AloecryptEncapsulator, AloecryptPEM, AloecryptSignable, AloecryptSigner, AloecryptVerifier, AloecryptPasswordPEM};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};

#[derive(Clone)]
struct TestParty {
    root_signer: DilithiumSigner,
    delegate_signer: DilithiumSigner,
    root_kem: KyberFullKEM,
    msg_kem: KyberFullKEM,
    secure_session: Option<SessionBuilder>
}

impl TestParty {
    fn new() -> Self{
        let mut os_rng = OsRng;
        let root_signer = DilithiumSigner::new(&mut os_rng);
        let root_kem = root_signer.canonical_kyber_kem(&[0u8], EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
        
        let delegate_signer = root_signer.create_dilithium_signer(&mut os_rng, EMPTY_TIMESTAMP,EMPTY_TIMESTAMP, 0, 0);
        let msg_kem = delegate_signer.canonical_kyber_kem(&[0u8], EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);
        
        Self {
            root_signer,
            delegate_signer,
            root_kem,
            msg_kem,
            secure_session: None
        }
    }
    fn address(&self) -> [u8; ADDRESS_SZ] { self.root_signer.dlt_address }

    fn start_session(&mut self, counterparty_address: [u8; ADDRESS_SZ]) {
        self.secure_session  = Some(SessionBuilder::new(counterparty_address, self.delegate_signer));
    }
}

use ml_kem::EncodedSizeUser;
use zerocopy::IntoBytes;
use hybrid_array::Array;
use std::result::Result::{Err,Ok};

fn main() {
    let mut os_rng = OsRng;
    let mut party_a = TestParty::new();
    let mut party_b = TestParty::new();

    party_a.start_session(party_b.address());
    party_b.start_session(party_a.address());
    if let (Some(mut session_a), Some(mut session_b)) = (party_a.secure_session, party_b.secure_session) {

        let msg_hello = MsgHELLO{
            address: session_a.address(),
            intro: session_a.make_party_intro()
        };

        println!("");
        println!("====================================");
        println!("Party B Recv MsgHELLO:");
        println!("====================================");
        println!("--- on_counterparty_intro ---");
        match session_b.on_counterparty_intro(&msg_hello.intro) {
            Err(e)=>{println!("AloecryptSessionError: {}",e);}
            _=> { println!("--- OK! ---"); }
        }

        println!("");
        println!("====================================");
        println!("Party B Send MsgSYN:");
        println!("====================================");
        let session_b_intro = session_b.make_party_intro();
        let session_b_cipher = session_b.make_party_cipher().unwrap();
        let msg_syn = MsgSYN {
            intro: session_b_intro,
            cipher: session_b_cipher,
        };

        println!("");
        println!("====================================");
        println!("Party A Recv MsgSYN:");
        println!("====================================");
        println!("--- on_counterparty_intro ---");
        match session_a.on_counterparty_intro(&msg_syn.intro) {
            Err(e)=>{println!("AloecryptSessionError: {}",e);}
            _=> { println!("--- OK! ---"); }
        }
        println!("--- on_counterparty_cipher ---");
        match session_a.on_counterparty_cipher(msg_syn.cipher) {
            Err(e)=>{println!("AloecryptSessionError: {}",e);}
            _=> { println!("--- OK! ---"); }
        }

        println!("");
        println!("====================================");
        println!("Party A Send MsgACK:");
        println!("====================================");
        let session_a_cipher = session_a.make_party_cipher().unwrap();
        let session_a_challenge = session_a.make_party_challenge().unwrap();
        let msg_ack = MsgACK {
            cipher: session_a_cipher,
            challenge: session_a_challenge,
        };

        println!("");
        println!("====================================");
        println!("Party B Recv MsgACK:");
        println!("====================================");
        println!("--- on_counterparty_cipher ---");
        match session_b.on_counterparty_cipher(msg_ack.cipher) {
            Err(e)=>{println!("AloecryptSessionError: {}",e);}
            _=> { println!("--- OK! ---"); }
        }
        println!("--- on_counterparty_challenge ---");
        match session_b.on_counterparty_challenge(msg_ack.challenge) {
            Err(AloecryptSessionError::RecvDecryptError(e))=>{println!("AloecryptSessionError::RecvDecryptError: {}",e);}
            Err(AloecryptSessionError::NoCounterPartyCIPHER)=>{println!("AloecryptSessionError::NoCounterPartyCIPHER");}
            Err(AloecryptSessionError::NoCounterPartyINTRO)=>{println!("AloecryptSessionError::NoCounterPartyINTRO");}
            _=> { println!("--- OK! ---"); }
        }

        println!("");
        println!("====================================");
        println!("Party B Send MsgSYNACK:");
        println!("====================================");
        let session_b_challenge = session_b.make_party_challenge().unwrap();
        let session_b_challenge_response = session_b.make_party_challenge_response().unwrap();

        let msg_synack = MsgSYNACK {
            challenge: session_b_challenge,
            challenge_response: session_b_challenge_response,
        };

        println!("");
        println!("====================================");
        println!("Party A Recv MsgSYNACK:");
        println!("====================================");

        println!("--- on_counterparty_challenge ---");
        match session_a.on_counterparty_challenge(msg_synack.challenge) {
            Err(AloecryptSessionError::RecvDecryptError(e))=>{println!("AloecryptSessionError::RecvDecryptError: {}",e);}
            Err(AloecryptSessionError::NoCounterPartyCIPHER)=>{println!("AloecryptSessionError::NoCounterPartyCIPHER");}
            Err(AloecryptSessionError::NoCounterPartyINTRO)=>{println!("AloecryptSessionError::NoCounterPartyINTRO");}
            _=> { println!("--- OK! ---"); }
        }
        println!("--- on_counterparty_challenge_response ---");
        match session_a.on_counterparty_challenge_response(msg_synack.challenge_response) {
            Err(AloecryptSessionError::CounterPartyChallengeMismatch)=>{println!("CounterPartyChallengeMismatch");}
            _=> { println!("--- OK! ---"); }
        }

        println!("");
        println!("====================================");
        println!("Party A Send MsgWELCOME:");
        println!("====================================");

        let session_a_challenge_response = session_a.make_party_challenge_response().unwrap();
        let msg_welcome = MsgWELCOME {
            challenge_response: session_a_challenge_response,
        };

        println!("");
        println!("====================================");
        println!("Party B Recv MsgWELCOME:");
        println!("====================================");

        println!("--- on_counterparty_challenge_response ---");        
        match session_b.on_counterparty_challenge_response(msg_welcome.challenge_response) {
            Err(AloecryptSessionError::CounterPartyChallengeMismatch)=>{println!("CounterPartyChallengeMismatch");}
            _=> { println!("--- OK! ---"); }
        }


        println!("");
        println!("====================================");
        println!("Building Sessions:");
        println!("====================================");

        let built_session_a = session_a.build().unwrap();
        let built_session_b = session_b.build().unwrap();
        println!("--- Sessions Built OK! ---");

        println!("");
        println!("====================================");
        println!("Party A -> Party B: Message 1");
        println!("====================================");

        let plaintext_1 = b"Hello from Party A!";
        let encrypted_1 = built_session_a.encrypt(plaintext_1).unwrap();
        let decrypted_1 = built_session_b.decrypt(&encrypted_1).unwrap();
        assert_eq!(decrypted_1, b"Hello from Party A!");

        println!("Sent:     {:?}", std::str::from_utf8(plaintext_1).unwrap());
        println!("Received: {:?}", std::str::from_utf8(&decrypted_1).unwrap());
        assert_eq!(plaintext_1.to_vec(), decrypted_1, "Message 1 mismatch!");
        println!("--- Message 1 OK! ---");

        println!("");
        println!("====================================");
        println!("Party B -> Party A: Message 2");
        println!("====================================");

        let plaintext_2 = b"Hello back from Party B!";
        let encrypted_2 = built_session_b.encrypt(plaintext_2).unwrap();
        let decrypted_2 = built_session_a.decrypt(&encrypted_2).unwrap();
        assert_eq!(decrypted_2, b"Hello back from Party B!");

        println!("Sent:     {:?}", std::str::from_utf8(plaintext_2).unwrap());
        println!("Received: {:?}", std::str::from_utf8(&decrypted_2).unwrap());
        assert_eq!(plaintext_2.to_vec(), decrypted_2, "Message 2 mismatch!");
        println!("--- Message 2 OK! ---");

    }
    else {
        panic!("Sessions should be loaded and accessible/mutable");
    }
}
