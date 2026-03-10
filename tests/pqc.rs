// tests/pqc.rs

use aloecrypt::error::AloecryptError;
use ml_kem::kem::{Decapsulate, Encapsulate};
use rand_core::{OsRng, RngCore};

use aloecrypt::signatory::{DilithiumSigner,DilithiumVerifier};
use aloecrypt::kem::{KyberFullKEM, KyberPublicKEM};
use aloecrypt::consts::*;

use aloecrypt::traits::{AloecryptDecapsulator, AloecryptEncapsulator, AloecryptSignable, AloecryptSigner, AloecryptVerifier};

mod common;
use common::common::test as crosstest;

#[crosstest]
fn instantiate_and_verify_signatures() {
    let mut os_rng = OsRng;
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;
    
    let dilithium_signer = DilithiumSigner::new(&mut os_rng);
    let dilithium_verifier : DilithiumVerifier = dilithium_signer.into();
    
    let kyber_full_kem = dilithium_signer.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);
    let kyber_public_kem : KyberPublicKEM  = kyber_full_kem.into();

    let result_1 = dilithium_verifier.verify(dilithium_signer.signing_material(), dilithium_signer.dlt_sig_bytes);
    match result_1 {
        Ok(value) => assert_eq!(value, ()),
        Err(e) => panic!("Signature Varification Failed! {}", e)
    }
    let result_2 = dilithium_verifier.verify(kyber_full_kem.signing_material(), kyber_full_kem.kyb_sig_bytes);
    match result_2 {
        Ok(value) => assert_eq!(value, ()),
        Err(e) => panic!("Signature Varification Failed! {}", e)
    }
    let result_3 = dilithium_verifier.verify(kyber_public_kem.signing_material(), kyber_public_kem.kyb_sig_bytes);
    match result_3 {
        Ok(value) => assert_eq!(value, ()),
        Err(e) => panic!("Signature Varification Failed! {}", e)
    }
}

#[crosstest]
fn sign_and_verify() {
    let mut os_rng = OsRng;
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;


    let dilithium_root_signer = DilithiumSigner::new(&mut os_rng);
    let dilithium_root_verifier : DilithiumVerifier = dilithium_root_signer.into();
    
    const MSG2: &[u8] = b"Hello world this is a longer message. It was the best of times, it was the... blurst of times?!";
    let signature = dilithium_root_signer.sign(MSG2.into());

    dilithium_root_verifier.verify(MSG2.into(), signature);

    let derivative_signer = dilithium_root_signer.create_dilithium_signer(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);

    assert!(!derivative_signer.is_root_signer());
    assert_eq!(derivative_signer.dlt_address, dilithium_root_signer.dlt_address);
    assert_eq!(derivative_signer.dlt_auth_id, dilithium_root_signer.signing_auth_id());
    assert_ne!(derivative_signer.dlt_pubkey, dilithium_root_signer.dlt_pubkey);
    assert_ne!(derivative_signer.dlt_privkey, dilithium_root_signer.dlt_privkey);
    assert_ne!(derivative_signer.dlt_sig_bytes, dilithium_root_signer.dlt_sig_bytes);
    
    let root_verify_result = dilithium_root_signer.verify(derivative_signer.signing_material(), derivative_signer.dlt_sig_bytes);

    match root_verify_result {
        Ok(value) => assert_eq!(value, ()),
        Err(e) => panic!("Signature Varification Failed (Root Verifies Derivative)! {}", e)
    }

    let self_verify_result = derivative_signer.verify(derivative_signer.signing_material(), derivative_signer.dlt_sig_bytes);
    match self_verify_result {
        Ok(value) => panic!("Signature Varification Should Fail (Derivative Cannot Verify Self)!"),
        Err(e) => { }
    }
}

#[crosstest]
fn encapsultate_and_decapsulate_secret() {
    let mut os_rng = OsRng;
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;

    let dilithium_signer_b = DilithiumSigner::new(&mut os_rng);
    let kyber_full_kem_b = dilithium_signer_b.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);
    let kyber_public_kem_b : KyberPublicKEM = kyber_full_kem_b.into();

    let (cipher_text, sent_shared_key) = kyber_public_kem_b.encapsulation_key().encapsulate(&mut os_rng).unwrap();
    let recv_shared_key = kyber_full_kem_b.decapsulation_key().decapsulate(&cipher_text).unwrap();
    
    assert_eq!(sent_shared_key, recv_shared_key);
}


#[crosstest]
fn encapsultate_and_decapsulate() {
    let mut os_rng = OsRng;
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;

    let dilithium_signer_a: DilithiumSigner = DilithiumSigner::new(&mut os_rng);
    let dilithium_verifier_a : DilithiumVerifier = dilithium_signer_a.into();
    let kyber_full_kem_a = dilithium_signer_a.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);

    let kyber_public_kem_a : KyberPublicKEM = kyber_full_kem_a.into();

    let dilithium_signer_b : DilithiumSigner = DilithiumSigner::new(&mut os_rng);
    let dilithium_verifier_b : DilithiumVerifier  = dilithium_signer_b.into();
    let kyber_full_kem_b = dilithium_signer_b.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);


    let kyber_public_kem_b : KyberPublicKEM  = kyber_full_kem_b.into();

    let (cipher_text, sent_shared_key) = kyber_public_kem_b.encapsulation_key().encapsulate(&mut os_rng).unwrap();
    let recv_shared_key = kyber_full_kem_b.decapsulation_key().decapsulate(&cipher_text).unwrap();
    
    assert_eq!(sent_shared_key, recv_shared_key);
}