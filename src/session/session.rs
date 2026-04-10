// src/session/session.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use super::util::{cipher_pair, cipher_salt, nonce_pair, session_salt};
use crate::error::AloecryptSessionError;

impl IAloecryptSession for AloecryptSession {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
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

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AloecryptSessionError> {
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

    fn from_secrets(
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
