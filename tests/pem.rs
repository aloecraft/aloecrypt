// tests/pqc.rs

use ml_kem::kem::{Decapsulate, Encapsulate};
use rand_core::{OsRng, RngCore};

use aloecrypt::signatory::{DilithiumSigner,DilithiumVerifier};
use aloecrypt::kem::{KyberFullKEM, KyberPublicKEM};

use aloecrypt::consts::*;
use aloecrypt::traits::{AloecryptDecapsulator, AloecryptEncapsulator, AloecryptPEM, AloecryptSignable, AloecryptSigner, AloecryptVerifier, AloecryptPasswordPEM};
use chacha20poly1305::Nonce;

#[test]
fn load_and_unload_pem() {
    let mut os_rng = OsRng;

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    let dilithium_signer = DilithiumSigner::new(&mut os_rng);
    let signer_file = dilithium_signer.x_pem(keyfile_password, keyfile_salt);
    let loaded_signer = DilithiumSigner::x_loads(signer_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let dilithium_verifier : DilithiumVerifier = loaded_signer.into();
    let verifier_file = dilithium_verifier.pem();
    let loaded_verifier = DilithiumVerifier::loads(verifier_file.as_str()).unwrap();
    
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;
    let kyber_full_kem = loaded_signer.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);
    
    let kyber_full_file = kyber_full_kem.x_pem(keyfile_password, keyfile_salt);
    let loaded_kyber_full_kem = KyberFullKEM::x_loads(kyber_full_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let kyber_public_kem : KyberPublicKEM  = loaded_kyber_full_kem.into();
    let kyber_public_file = kyber_public_kem.pem();
    let loaded_kyber_public_kem = KyberPublicKEM::loads(kyber_public_file.as_str()).unwrap();
}

#[test]
fn verify_loaded_pem() {
    let mut os_rng = OsRng;

    let keyfile_salt = b"Test Salt!";
    let keyfile_password = b"Test Password!";

    let dilithium_signer = DilithiumSigner::new(&mut os_rng);
    let signer_file = dilithium_signer.x_pem(keyfile_password, keyfile_salt);
    let loaded_signer = DilithiumSigner::x_loads(signer_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let dilithium_verifier : DilithiumVerifier = loaded_signer.into();
    let verifier_file = dilithium_verifier.pem();
    let loaded_verifier = DilithiumVerifier::loads(verifier_file.as_str()).unwrap();
    let dlt_active_from =  EMPTY_TIMESTAMP;
    let dlt_expires_at =  EMPTY_TIMESTAMP;
    let dlt_refresh_count = 0;
    let dlt_max_refresh = 0;
    let kyber_full_kem = loaded_signer.create_kyber_kem(&mut os_rng,
        dlt_active_from,
        dlt_expires_at,
        dlt_refresh_count,
        dlt_max_refresh);
    
    let kyber_full_file = kyber_full_kem.x_pem(keyfile_password, keyfile_salt);
    let loaded_kyber_full_kem = KyberFullKEM::x_loads(kyber_full_file.as_str(), keyfile_password, keyfile_salt).unwrap();
    let kyber_public_kem : KyberPublicKEM  = loaded_kyber_full_kem.into();
    let kyber_public_file = kyber_public_kem.pem();
    let loaded_kyber_public_kem = KyberPublicKEM::loads(kyber_public_file.as_str()).unwrap();

    dilithium_verifier.verify(loaded_verifier.signing_material(), loaded_verifier.dlt_sig_bytes);
    loaded_verifier.verify(dilithium_signer.signing_material(), dilithium_signer.dlt_sig_bytes);
    loaded_verifier.verify(dilithium_verifier.signing_material(), dilithium_verifier.dlt_sig_bytes);
    loaded_verifier.verify(loaded_verifier.signing_material(), loaded_verifier.dlt_sig_bytes);
    loaded_verifier.verify(kyber_full_kem.signing_material(), kyber_full_kem.kyb_sig_bytes);
    loaded_verifier.verify(kyber_public_kem.signing_material(), kyber_public_kem.kyb_sig_bytes);
    loaded_verifier.verify(loaded_kyber_full_kem.signing_material(), loaded_kyber_full_kem.kyb_sig_bytes);
    loaded_verifier.verify(loaded_kyber_public_kem.signing_material(), loaded_kyber_public_kem.kyb_sig_bytes);
}