use super::util::{cipher_pair, cipher_salt, nonce_pair, session_salt};
use crate::session::message::{send_encrypt, recv_decrypt};
use crate::session::builder::{FullCIPHER, PartySecret};
use crate::error::AloecryptSessionError;
use crate::kem::{KyberFullKEM, KyberPublicKEM};
use crate::signatory::{DilithiumSigner, DilithiumVerifier};
use crate::traits::{
    AloecryptDecapsulator, AloecryptEncapsulator, AloecryptSigner, AloecryptVerifier,
};

use crate::consts::*;

use rand_core::OsRng;
use rand_core::RngCore;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
use hkdf::{Hkdf, HkdfExtract};
use hybrid_array::Array;
use ml_kem::EncodedSizeUser;
use ml_kem::kem::{Decapsulate, Encapsulate};
use pbkdf2::pbkdf2_hmac;
use zerocopy::IntoBytes;

#[derive(Clone, Copy)]
pub struct CounterParty {
    pub address: [u8; ADDRESS_SZ],
    pub nonce: [u8; SESSION_NONCE_SZ],
    pub signature: [u8; SIGNATURE_SZ],
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
}

#[derive(Clone, Copy)]
pub struct Party {
    pub nonce: [u8; SESSION_NONCE_SZ],
    pub session_signature: [u8; SIGNATURE_SZ],
    pub delegate_signer: DilithiumSigner,
    pub stable_kem: KyberFullKEM,
    pub session_kem: KyberFullKEM,
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
}

#[derive(Clone, Copy)]
pub struct AloecryptSession {
    pub party: Party,
    pub counter_party: CounterParty,
    pub session_salt: [u8; SESSION_SALT_SZ],
}

impl AloecryptSession {
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
        let sender = FullCIPHER {
            stable_cipher: [0u8; CIPHER_SZ],
            session_cipher: [0u8; CIPHER_SZ],
            stable_secret: self.party.stable_secret,
            session_secret: self.party.session_secret,
            signature: self.party.session_signature,
        };
        let receiver = PartySecret {
            stable_secret: self.counter_party.stable_secret,
            session_secret: self.counter_party.session_secret,
            signature: self.counter_party.signature,
        };
        send_encrypt(
            plaintext,
            sender,
            receiver,
            &self.session_salt,
            &self.counter_party.nonce,
            &self.counter_party.address,
            &self.party.nonce,
            &self.party.delegate_signer.dlt_address,
        )
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
        let sender = PartySecret {
            stable_secret: self.counter_party.stable_secret,
            session_secret: self.counter_party.session_secret,
            signature: self.counter_party.signature,
        };
        let receiver = FullCIPHER {
            stable_cipher: [0u8; CIPHER_SZ],
            session_cipher: [0u8; CIPHER_SZ],
            stable_secret: self.party.stable_secret,
            session_secret: self.party.session_secret,
            signature: self.party.session_signature,
        };
        recv_decrypt(
            ciphertext,
            sender,
            receiver,
            &self.session_salt,
            &self.party.nonce,
            &self.party.delegate_signer.dlt_address,
            &self.counter_party.nonce,
            &self.counter_party.address,
        )
    }
}