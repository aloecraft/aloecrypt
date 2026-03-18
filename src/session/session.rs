// src/session/session.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::util::{cipher_pair, cipher_salt, nonce_pair, session_salt};
use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::error::AloecryptSessionError;
use crate::kem::{KyberFullKEM, KyberPublicKEM};
use crate::session::builder::{CounterPartySECRET, FullCIPHER};
use crate::session::message::{recv_decrypt, send_encrypt};
use crate::session::party::*;
use crate::signatory::{DilithiumSigner, DilithiumVerifier};
use crate::traits::{
    AloecryptDecapsulator, AloecryptEncapsulator, AloecryptSigner, AloecryptVerifier,
};
use crate::types::*;

use crate::option_big_array;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
use hkdf::{Hkdf, HkdfExtract};
use hybrid_array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zerocopy::IntoBytes;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct AloecryptSession {
    pub party: Party,
    pub counter_party: CounterParty,
    pub session_salt: AloecryptSessionSalt,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct XAloecryptSession {
    pub x_party: XParty,
    pub x_counter_party: XCounterParty,
    #[serde(with = "BigArray")]
    pub x_session_salt: XAloecryptSessionSalt,
    pub un_hash: AloecryptHash,
    pub priv_hash: AloecryptHash,
}

impl AloecryptSession {
    pub fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut os_rng: &mut impl RngCore,
    ) -> Result<XAloecryptSession, AloecryptError> {
        let x_party = self.party.lock_with_password(password, salt, &mut os_rng)?;
        let x_counter_party = self
            .counter_party
            .lock_with_password(password, salt, &mut os_rng)?;
        let x_session_salt_vec = password_encrypt(
            &self.session_salt,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_counter_party.crypt_nonce),
        )?;
        let x_session_salt: [u8; SESSION_SALT_SZ + ENCRYPTED_TAG_SZ] = x_session_salt_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        Ok(XAloecryptSession {
            x_party,
            x_counter_party,
            x_session_salt,
            un_hash: self.hash(),
            priv_hash: self.priv_hash(),
        })
    }

    pub fn unlock_with_password(
        x_session: XAloecryptSession,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let party = Party::unlock_with_password(x_session.x_party, password, salt)?;
        let counter_party =
            CounterParty::unlock_with_password(x_session.x_counter_party, password, salt)?;
        let session_salt_vec = password_decrypt(
            &x_session.x_session_salt,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_session.x_counter_party.crypt_nonce),
        )?;
        let session_salt: [u8; SESSION_SALT_SZ] = session_salt_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        Ok(Self {
            party,
            counter_party,
            session_salt,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
        let sender = FullCIPHER {
            stable_cipher: EMPTY_CIPHER,
            session_cipher: EMPTY_CIPHER,
            stable_secret: self.party.stable_secret,
            session_secret: self.party.session_secret,
            signature: self.party.session_signature,
        };
        let receiver = CounterPartySECRET {
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
            &self.counter_party.address(),
            &self.party.nonce,
            &self.party.delegate_signer.address(),
        )
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
        let sender = CounterPartySECRET {
            stable_secret: self.counter_party.stable_secret,
            session_secret: self.counter_party.session_secret,
            signature: self.counter_party.signature,
        };
        let receiver = FullCIPHER {
            stable_cipher: EMPTY_CIPHER,
            session_cipher: EMPTY_CIPHER,
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
            &self.party.delegate_signer.address(),
            &self.counter_party.nonce,
            &self.counter_party.address(),
        )
    }

    pub fn from_secrets(
        // Party (self) side
        party_stable_secret: AloecryptSecret,
        party_session_secret: AloecryptSecret,
        party_session_signature: DilithiumSignature,
        party_nonce: AloecryptSessionNonce,
        party_address: AloecryptAddress,
        // Counterparty side
        counterparty_stable_secret: AloecryptSecret,
        counterparty_session_secret: AloecryptSecret,
        counterparty_signature: DilithiumSignature,
        counterparty_nonce: AloecryptSessionNonce,
        counterparty_address: AloecryptAddress,
        // Shared
        session_salt: AloecryptSessionSalt,
    ) -> Self {
        let mut party = Party::empty();
        party.stable_secret = party_stable_secret;
        party.session_secret = party_session_secret;
        party.session_signature = party_session_signature;
        party.nonce = party_nonce;
        party.delegate_signer.dlt_auth_address = party_address;

        let mut counter_party = CounterParty::empty();
        counter_party.stable_secret = counterparty_stable_secret;
        counter_party.session_secret = counterparty_session_secret;
        counter_party.signature = counterparty_signature;
        counter_party.nonce = counterparty_nonce;
        counter_party.address = counterparty_address;

        Self {
            party,
            counter_party,
            session_salt,
        }
    }
}
// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
