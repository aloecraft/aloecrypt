use super::util::{cipher_pair, cipher_salt, nonce_pair, session_salt};
use super::*;
use crate::consts::*;
use crate::crypt::CryptNonce;
use crate::error::AloecryptSessionError;
use crate::kem::*;
use crate::session::message::{
    MsgACK, MsgHELLO, MsgSYN, MsgSYNACK, MsgWELCOME, recv_decrypt, send_encrypt,
};
use crate::signatory::{DilithiumSigner, DilithiumVerifier};
use crate::traits::AloecryptAddressable;
use crate::traits::{
    AloecryptDecapsulator, AloecryptEncapsulator, AloecryptSigner, AloecryptVerifier,
};
use crate::types::*;

use crate::option_big_array;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PartyINTRO {
    pub address: AloecryptAddress,
    pub nonce: [u8; SESSION_NONCE_SZ],
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PartyCIPHER {
    #[serde(with = "BigArray")]
    pub stable_cipher: KyberCipher,
    #[serde(with = "BigArray")]
    pub session_cipher: KyberCipher,
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct FullCIPHER {
    #[serde(with = "BigArray")]
    pub stable_cipher: KyberCipher,
    #[serde(with = "BigArray")]
    pub session_cipher: KyberCipher,
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CounterPartySECRET {
    pub stable_secret: [u8; SECRET_SZ],
    pub session_secret: [u8; SECRET_SZ],
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PartyCHALLENGE {
    #[serde(with = "BigArray")]
    pub encrypted_challenge: [u8; ENCRYPTED_NONCE_SZ],
    #[serde(with = "BigArray")]
    pub encrypted_check: [u8; ENCRYPTED_NONCE_SZ],
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PartyRESPONSE {
    pub decrypted_challenge: [u8; SESSION_NONCE_SZ],
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CounterPartyCHALLENGE {
    pub decrypted_challenge: [u8; SESSION_NONCE_SZ],
    pub decrypted_check: [u8; SESSION_NONCE_SZ],
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct FromSecretsInput {
    pub stable_secret_a: [u8; SECRET_SZ],
    pub session_secret_a: [u8; SECRET_SZ],
    #[serde(with = "BigArray")]
    pub signature_a: DilithiumSignature,
    pub nonce_a: [u8; SESSION_NONCE_SZ],
    pub address_a: AloecryptAddress,
    pub stable_secret_b: [u8; SECRET_SZ],
    pub session_secret_b: [u8; SECRET_SZ],
    #[serde(with = "BigArray")]
    pub signature_b: DilithiumSignature,
    pub nonce_b: [u8; SESSION_NONCE_SZ],
    pub address_b: AloecryptAddress,
    pub session_salt: [u8; SESSION_SALT_SZ],
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
        os_rng: &mut (impl rand_chacha::rand_core::CryptoRng + ?Sized),
    ) -> Result<FullCIPHER, AloecryptSessionError> {
        let ((stable_cipher, stable_secret), (session_cipher, session_secret)) = (
            self.stable_kem
                .encapsulation_key()
                .encapsulate_with_rng(os_rng),
            self.session_kem
                .encapsulation_key()
                .encapsulate_with_rng(os_rng),
        );
        Ok(FullCIPHER {
            stable_cipher: stable_cipher.into(),
            session_cipher: session_cipher.into(),
            stable_secret: stable_secret.into(),
            session_secret: session_secret.into(),
            signature: signature,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct SessionBuilder {
    pub delegate_signer: DilithiumSigner,
    pub stable_kem: KyberFullKEM,
    pub session_kem: KyberFullKEM,
    pub nonce: [u8; SESSION_NONCE_SZ],
    pub challenge_nonce: [u8; SESSION_NONCE_SZ],
    pub session_salt: Option<[u8; SESSION_SALT_SZ]>,
    #[serde(with = "option_big_array")]
    pub signature: Option<DilithiumSignature>,
    pub cipher: Option<FullCIPHER>,
    pub counterparty_intro: Option<PartyINTRO>,
    pub counterparty_cipher: Option<CounterPartySECRET>,
    pub counterparty_challenge: Option<CounterPartyCHALLENGE>,
    pub build_ready: bool,
}

impl SessionBuilder {
    pub fn new(
        counterparty_address: [u8; ADDRESS_SZ],
        delegate_signer: DilithiumSigner,
        mut os_rng: &mut impl SysRng,
    ) -> Self {
        let mut nonce = [0u8; SESSION_NONCE_SZ];
        os_rng.try_fill_bytes(&mut nonce);
        let mut challenge_nonce = [0u8; SESSION_NONCE_SZ];
        os_rng.try_fill_bytes(&mut challenge_nonce);

        let stable_kem = delegate_signer.canonical_kyber_kem(
            &counterparty_address,
            EMPTY_TIMESTAMP,
            EMPTY_TIMESTAMP,
            0,
            0,
        );

        let session_kem =
            delegate_signer.create_kyber_kem(&mut os_rng, EMPTY_TIMESTAMP, EMPTY_TIMESTAMP, 0, 0);

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
}

impl AloecryptSessionBuilder for SessionBuilder {
    fn on_counterparty_intro(
        &mut self,
        counterparty_intro: &PartyINTRO,
        os_rng: &mut dyn rand_chacha::rand_core::CryptoRng,
    ) -> Result<(), AloecryptSessionError> {
        let session_salt = PartyINTRO::make_salt(&self.make_party_intro(), counterparty_intro);
        let signature: [u8; 3309] = self.delegate_signer.sign(session_salt.into());

        match counterparty_intro.make_cipher(signature, os_rng) {
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
    fn on_counterparty_cipher(
        &mut self,
        counterparty_cipher: PartyCIPHER,
    ) -> Result<(), AloecryptSessionError> {
        let (counterparty_stable_shared_key, counterparty_session_shared_key) = (
            self.stable_kem
                .decapsulation_key()
                .decapsulate((&counterparty_cipher.stable_cipher).into()),
            self.session_kem
                .decapsulation_key()
                .decapsulate((&counterparty_cipher.session_cipher).into()),
        );
        self.counterparty_cipher = Some(CounterPartySECRET {
            stable_secret: counterparty_stable_shared_key.into(),
            session_secret: counterparty_session_shared_key.into(),
            signature: counterparty_cipher.signature,
        });
        Ok(())
    }
    fn on_counterparty_challenge(
        &mut self,
        counterparty_challenge: PartyCHALLENGE,
    ) -> Result<(), AloecryptSessionError> {
        if let (Some(cipher), Some(counterparty_intro), Some(session_salt)) =
            (self.cipher, self.counterparty_intro, self.session_salt)
        {
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
                if decrypted_check == self.nonce {
                    self.counterparty_challenge = Some(CounterPartyCHALLENGE {
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
    fn on_counterparty_challenge_response(
        &mut self,
        counterparty_challenge_response: PartyRESPONSE,
    ) -> Result<(), AloecryptSessionError> {
        if counterparty_challenge_response.decrypted_challenge == self.challenge_nonce {
            self.build_ready = true;
            Ok(())
        } else {
            Err(AloecryptSessionError::CounterPartyChallengeMismatch)
        }
    }
    fn make_party_intro(&self) -> PartyINTRO {
        PartyINTRO {
            address: self.address(),
            nonce: self.nonce,
            stable_kem: self.stable_kem.into(),
            session_kem: self.session_kem.into(),
            verifier: self.delegate_signer.into(),
        }
    }
    fn make_party_challenge(&self) -> Result<PartyCHALLENGE, AloecryptSessionError> {
        let counterparty_cipher = self
            .counterparty_cipher
            .as_ref()
            .ok_or(AloecryptSessionError::NoCounterPartyCIPHER)?;
        if let (Some(cipher), Some(counterparty_intro), Some(session_salt)) =
            (self.cipher, self.counterparty_intro, self.session_salt)
        {
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
            Ok(PartyCHALLENGE {
                encrypted_challenge: encrypted_challenge.try_into().expect("msg"),
                encrypted_check: encrypted_check.try_into().expect("msg"),
            })
        } else {
            Err(AloecryptSessionError::NoCounterPartyINTRO)
        }
    }

    fn make_party_challenge_response(&self) -> Result<PartyRESPONSE, AloecryptSessionError> {
        if let Some(counterparty_challenge) = self.counterparty_challenge {
            Ok(PartyRESPONSE {
                decrypted_challenge: counterparty_challenge.decrypted_challenge,
            })
        } else {
            Err(AloecryptSessionError::NoCounterPartyCHALLENGE)
        }
    }

    fn make_party_cipher(&self) -> Result<PartyCIPHER, AloecryptSessionError> {
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

    fn build(&self) -> Result<AloecryptSession, AloecryptSessionError> {
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
