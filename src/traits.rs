use chacha20poly1305::Nonce;
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};
use ml_kem::MlKem768Params;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};

use crate::consts::*;
use crate::error::AloecryptError;

// PEM File Traits
// ==================
pub trait AloecryptPEM {
    fn byte_sz() -> usize;
    fn pem(&self) -> String;
    fn loads(pem: &str) -> Result<Self, AloecryptError>
    where
        Self: Sized;
}

pub trait AloecryptPasswordPEM {
    fn x_pem(&self, password: &[u8], salt: &[u8]) -> String;
    fn x_loads(
        pem: &str,
        password: &[u8],
        salt: &[u8]
    ) -> Result<Self, AloecryptError>
    where
        Self: Sized;
}

// Cipher Traits
// ==================
pub trait AloecryptEncapsulator {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768Params>;
}

pub trait AloecryptDecapsulator {
    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768Params>;
}

// Signatory Traits
// ==================
pub trait AloecryptVerifier {
    fn verifying_key(&self) -> VerifyingKey<MlDsa65>;
    fn verify(&self, signing_material: Vec<u8>, sig_bytes: [u8; SIGNATURE_SZ]) -> Result<(), AloecryptError>{
        let signature =
            Signature::<MlDsa65>::decode(&sig_bytes.into()).expect("Error decoding signature!");
        self.verifying_key().verify(&(*signing_material), &signature).map_err(|e| {AloecryptError::Signature})
    }
}

pub trait AloecryptSigner {
    fn signing_key(&self) -> SigningKey<MlDsa65>;
    fn sign(&self, signing_material: Vec<u8>) -> [u8; SIGNATURE_SZ] {
        self.signing_key()
            .sign(signing_material.as_slice())
            .encode()
            .into()
    }
}

pub trait AloecryptSignable {
    fn signing_material(&self) -> Vec<u8>;
}
