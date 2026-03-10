use super::util::{cipher_pair, cipher_salt, nonce_pair, session_salt};
use crate::error::AloecryptSessionError;
use crate::kem::{KyberFullKEM, KyberPublicKEM};
use crate::session::message::{
    MsgACK, MsgHELLO, MsgSYN, MsgSYNACK, MsgWELCOME, recv_decrypt, send_encrypt,
};
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

use super::session::{AloecryptSession, Party, CounterParty};

#[derive(Clone, Copy, Debug)]
pub struct PartyINTRO {
    pub address: [u8; ADDRESS_SZ],
    pub nonce: [u8; SESSION_NONCE_SZ],
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
}

#[derive(Clone, Copy, Debug)]
pub struct PartyCIPHER {
    pub stable_cipher: [u8; CIPHER_SZ],
    pub session_cipher: [u8; CIPHER_SZ],
    pub signature: [u8; SIGNATURE_SZ],
}

#[derive(Clone, Copy, Debug)]
pub struct FullCIPHER {
    pub stable_cipher: [u8; CIPHER_SZ],
    pub session_cipher: [u8; CIPHER_SZ],
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
    pub signature: [u8; SIGNATURE_SZ],
}

#[derive(Clone, Copy, Debug)]
pub struct PartySecret {
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
    pub signature: [u8; SIGNATURE_SZ],
}

#[derive(Clone, Copy, Debug)]
pub struct PartyCHALLENGE {
    pub encrypted_challenge: [u8; ENCRYPTED_NONCE_SZ],
    pub encrypted_check: [u8; ENCRYPTED_NONCE_SZ],
}

#[derive(Clone, Copy, Debug)]
pub struct PartyRESPONSE {
    pub decrypted_challenge: [u8; SESSION_NONCE_SZ],
}

#[derive(Clone, Copy, Debug)]
pub struct PartyChallenge {
    pub encrypted_challenge: [u8; ENCRYPTED_NONCE_SZ],
    pub encrypted_check: [u8; ENCRYPTED_NONCE_SZ],
    pub decrypted_challenge: [u8; SESSION_NONCE_SZ],
    pub decrypted_check: [u8; SESSION_NONCE_SZ],
}

impl PartyINTRO {
    pub fn make_salt(party_a: &PartyINTRO, party_b: &PartyINTRO) -> [u8; SESSION_SALT_SZ] {
        session_salt(
            party_a.nonce,
            party_b.nonce,
            party_a.address,
            party_b.address,
        )
    }
    pub fn make_cipher(
        &self,
        signature: [u8; SIGNATURE_SZ],
    ) -> Result<FullCIPHER, AloecryptSessionError> {
        let mut os_rng = OsRng;
        if let (
            Result::Ok((stable_cipher, stable_secret)),
            Result::Ok((session_cipher, session_secret)),
        ) = (
            self.stable_kem.encapsulation_key().encapsulate(&mut os_rng),
            self.session_kem
                .encapsulation_key()
                .encapsulate(&mut os_rng),
        ) {
            Ok(FullCIPHER {
                stable_cipher: stable_cipher.into(),
                session_cipher: session_cipher.into(),
                stable_secret: stable_secret.into(),
                session_secret: session_secret.into(),
                signature: signature,
            })
        } else {
            Err(AloecryptSessionError::EncapsulateError)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SessionBuilder {
    pub delegate_signer: DilithiumSigner,
    stable_kem: KyberFullKEM,
    session_kem: KyberFullKEM,
    nonce: [u8; SESSION_NONCE_SZ],
    challenge_nonce: [u8; SESSION_NONCE_SZ],
    session_salt: Option<[u8; SESSION_SALT_SZ]>,
    signature: Option<[u8; SIGNATURE_SZ]>,
    cipher: Option<FullCIPHER>,
    counterparty_intro: Option<PartyINTRO>,
    counterparty_cipher: Option<PartySecret>,
    counterparty_challenge: Option<PartyChallenge>,
    build_ready: bool,
}

impl SessionBuilder {
    pub fn address(&self) -> [u8; ADDRESS_SZ] {
        self.delegate_signer.dlt_address
    }
    pub fn new(counterparty_address: [u8; ADDRESS_SZ], delegate_signer: DilithiumSigner) -> Self {
        let mut os_rng = OsRng;

        let mut nonce = [0u8; SESSION_NONCE_SZ];
        os_rng.fill_bytes(&mut nonce);

        let stable_kem = delegate_signer.canonical_kyber_kem(
            &counterparty_address,
            EMPTY_TIMESTAMP,
            EMPTY_TIMESTAMP,
            0,
            0,
        );

        let session_kem =
            delegate_signer.create_kyber_kem(&mut os_rng, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);

        let mut challenge_nonce = [0u8; SESSION_NONCE_SZ];
        os_rng.fill_bytes(&mut challenge_nonce);

        Self {
            delegate_signer: delegate_signer,
            stable_kem: stable_kem,
            session_kem: session_kem,
            nonce: nonce,
            challenge_nonce: challenge_nonce,
            signature: None,
            session_salt: None,
            cipher: None,
            counterparty_intro: None,
            counterparty_cipher: None,
            counterparty_challenge: None,
            build_ready: false,
        }
    }

    pub fn make_party_intro(&self) -> PartyINTRO {
        PartyINTRO {
            address: self.address(),
            nonce: self.nonce,
            stable_kem: self.stable_kem.into(),
            session_kem: self.session_kem.into(),
            verifier: self.delegate_signer.into(),
        }
    }

    pub fn on_counterparty_intro(
        &mut self,
        counterparty_intro: &PartyINTRO,
    ) -> Result<(), AloecryptSessionError> {
        let session_salt = PartyINTRO::make_salt(&self.make_party_intro(), counterparty_intro);
        let signature: [u8; 3309] = self.delegate_signer.sign(session_salt.into());

        // println!("session_salt: {:x?}", session_salt);
        // println!("   signature: {:x?}...", &signature[0..20]);

        match counterparty_intro.make_cipher(signature) {
            Result::Ok(full_cipher) => {
                self.session_salt = Some(session_salt);
                self.cipher = Some(full_cipher);
                self.counterparty_intro = Some(counterparty_intro.clone());
                self.signature = Some(signature);
                Ok(())
            }
            Result::Err(e) => Err(e),
        }
    }

    pub fn on_counterparty_cipher(
        &mut self,
        counterparty_cipher: PartyCIPHER,
    ) -> Result<(), AloecryptSessionError> {
        if let (Result::Ok(counterparty_stable_secret), Result::Ok(counterparty_session_secret)) = (
            self.stable_kem
                .decapsulation_key()
                .decapsulate((&counterparty_cipher.stable_cipher).into()),
            self.session_kem
                .decapsulation_key()
                .decapsulate((&counterparty_cipher.session_cipher).into()),
        ) {
            self.counterparty_cipher = Some(PartySecret {
                stable_secret: counterparty_stable_secret.into(),
                session_secret: counterparty_session_secret.into(),
                signature: counterparty_cipher.signature,
            });
            Ok(())
        } else {
            Err(AloecryptSessionError::DecapsulateError)
        }
    }

    pub fn on_counterparty_challenge(
        &mut self,
        counterparty_challenge: PartyCHALLENGE,
    ) -> Result<(), AloecryptSessionError> {
        if let (Some(cipher), Some(counterparty_intro), Some(session_salt)) =
            (self.cipher, self.counterparty_intro, self.session_salt)
        {
            // println!("Receive Challenge:");
            // println!("    Self Nonce: {:x?}", self.nonce);
            // println!("---");
            // println!(
            //     "challenge(enc): {:x?}",
            //     counterparty_challenge.encrypted_challenge
            // );
            // println!(
            //     "    check(enc): {:x?}",
            //     counterparty_challenge.encrypted_check
            // );
            // println!("-----------");
            if let Some(counterparty_cipher) = self.counterparty_cipher {
                let decrypted_challenge = recv_decrypt(
                    &counterparty_challenge.encrypted_challenge,
                    counterparty_cipher,
                    cipher,
                    &session_salt,
                    &self.nonce,
                    &self.address(),
                    &counterparty_intro.nonce,
                    &counterparty_intro.address,
                )?;
                // &self.challenge_nonce,
                // println!("-----------");
                let decrypted_check = recv_decrypt(
                    &counterparty_challenge.encrypted_check,
                    counterparty_cipher,
                    cipher,
                    &session_salt,
                    &self.nonce,
                    &self.address(),
                    &counterparty_intro.nonce,
                    &counterparty_intro.address,
                )?;
                // println!("-----------");

                // println!("challenge: {:x?}", decrypted_challenge);
                // println!("    check: {:x?}", decrypted_check);

                if decrypted_check == self.nonce {
                    self.counterparty_challenge = Some(PartyChallenge {
                        encrypted_challenge: counterparty_challenge.encrypted_challenge,
                        encrypted_check: counterparty_challenge.encrypted_check,
                        decrypted_challenge: decrypted_challenge.try_into().expect("msg"),
                        decrypted_check: decrypted_check.try_into().expect("msg"),
                    });
                    Ok(())
                } else {
                    Err(AloecryptSessionError::CounterPartyCheckMismatch)
                }
            } else {
                Err(AloecryptSessionError::NoCounterPartyCIPHER)
            }
        } else {
            Err(AloecryptSessionError::NoCounterPartyINTRO)
        }
    }

    pub fn on_counterparty_challenge_response(
        &mut self,
        counterparty_challenge_response: PartyRESPONSE,
    ) -> Result<(), AloecryptSessionError> {
        // println!("Receive Challenge Response:");
        // println!("    Challenge Nonce: {:x?}", self.challenge_nonce);
        // println!("---");
        // println!(
        //     "challenge response: {:x?}",
        //     counterparty_challenge_response.decrypted_challenge
        // );
        if counterparty_challenge_response.decrypted_challenge == self.challenge_nonce {
            self.build_ready = true;
            Ok(())
        } else {
            Err(AloecryptSessionError::CounterPartyChallengeMismatch)
        }
    }

    pub fn make_party_challenge(&self) -> Result<PartyCHALLENGE, AloecryptSessionError> {
        let counterparty_cipher = self
            .counterparty_cipher
            .as_ref()
            .ok_or(AloecryptSessionError::NoCounterPartyCIPHER)?;
        if let (Some(cipher), Some(counterparty_intro), Some(session_salt)) =
            (self.cipher, self.counterparty_intro, self.session_salt)
        {
            // println!("Make Challenge:");
            // println!("receiver address: {:x?}", counterparty_intro.address);
            // println!("sender address: {:x?}", self.address());
            // println!("---");
            // println!("challenge: {:x?}", self.challenge_nonce);
            // println!("    check: {:x?}", counterparty_intro.nonce);

            // println!("-----------");
            let encrypted_challenge = send_encrypt(
                &self.challenge_nonce,
                cipher,
                *counterparty_cipher,
                &session_salt,
                &counterparty_intro.nonce,
                &counterparty_intro.address,
                &self.nonce,
                &self.address(),
            )?;
            // println!("-----------");
            let encrypted_check = send_encrypt(
                &counterparty_intro.nonce,
                cipher,
                *counterparty_cipher,
                &session_salt,
                &counterparty_intro.nonce,
                &counterparty_intro.address,
                &self.nonce,
                &self.address(),
            )?;
            // println!("-----------");
            // println!("challenge(enc): {:x?}", encrypted_challenge);
            // println!("    check(enc): {:x?}", encrypted_check);
            Ok(PartyCHALLENGE {
                encrypted_challenge: encrypted_challenge.try_into().expect("msg"),
                encrypted_check: encrypted_check.try_into().expect("msg"),
            })
        } else {
            Err(AloecryptSessionError::NoCounterPartyINTRO)
        }
    }

    pub fn make_party_challenge_response(&self) -> Result<PartyRESPONSE, AloecryptSessionError> {
        if let Some(counterparty_challenge) = self.counterparty_challenge {
            Ok(PartyRESPONSE {
                decrypted_challenge: counterparty_challenge.decrypted_challenge,
            })
        } else {
            Err(AloecryptSessionError::NoCounterPartyCHALLENGE)
        }
    }

    pub fn make_party_cipher(&self) -> Result<PartyCIPHER, AloecryptSessionError> {
        if let (Some(signature), Some(counterparty_intro)) =
            (self.signature, self.counterparty_intro)
        {
            if let (Some(signature), Some(cipher), Some(counterparty_intro)) =
                (self.signature, self.cipher, self.counterparty_intro)
            {
                Ok(PartyCIPHER {
                    stable_cipher: cipher.stable_cipher,
                    session_cipher: cipher.session_cipher,
                    signature: signature,
                })
            } else {
                Err(AloecryptSessionError::CipherNotReady)
            }
        } else {
            Err(AloecryptSessionError::NoCounterPartyINTRO)
        }
    }

    pub fn build(&self) -> Result<AloecryptSession, AloecryptSessionError> {
        if !self.build_ready {
            return Err(AloecryptSessionError::BuildNotReady);
        }

        let cipher = self.cipher.ok_or(AloecryptSessionError::CipherNotReady)?;
        let counterparty_intro = self
            .counterparty_intro
            .ok_or(AloecryptSessionError::NoCounterPartyINTRO)?;
        let counterparty_cipher = self
            .counterparty_cipher
            .ok_or(AloecryptSessionError::NoCounterPartyCIPHER)?;
        let session_salt = self
            .session_salt
            .ok_or(AloecryptSessionError::NoCounterPartyINTRO)?;

        Ok(AloecryptSession {
            party: Party {
                nonce: self.nonce,
                session_signature: self
                    .signature
                    .ok_or(AloecryptSessionError::CipherNotReady)?,
                delegate_signer: self.delegate_signer,
                stable_kem: self.stable_kem,
                session_kem: self.session_kem,
                stable_secret: cipher.stable_secret,
                session_secret: cipher.session_secret,
            },
            counter_party: CounterParty {
                address: counterparty_intro.address,
                nonce: counterparty_intro.nonce,
                signature: counterparty_cipher.signature,
                stable_kem: counterparty_intro.stable_kem,
                session_kem: counterparty_intro.session_kem,
                verifier: counterparty_intro.verifier,
                stable_secret: counterparty_cipher.stable_secret,
                session_secret: counterparty_cipher.session_secret,
            },
            session_salt,
        })
    }
}
