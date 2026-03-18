// src/session/hashable.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::builder::*;
use super::message::*;
use super::party::*;
use super::session::*;
use super::*;
use crate::util::_hash;

impl AloecryptHashable for PartyINTRO {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY_INTRO, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material =
            Vec::with_capacity(ADDRESS_SZ + SESSION_NONCE_SZ + HASH_SZ + HASH_SZ + HASH_SZ);
        hashing_material.extend_from_slice(&self.address);
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material.extend_from_slice(&self.stable_kem.hash());
        hashing_material.extend_from_slice(&self.session_kem.hash());
        hashing_material.extend_from_slice(&self.verifier.hash());
        hashing_material
    }
}

impl AloecryptHashable for PartyCIPHER {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY_CIPHER, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(CIPHER_SZ + CIPHER_SZ + SIGNATURE_SZ);
        hashing_material.extend_from_slice(&self.stable_cipher);
        hashing_material.extend_from_slice(&self.session_cipher);
        hashing_material.extend_from_slice(&self.signature);
        hashing_material
    }
}

impl AloecryptHashable for FullCIPHER {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY_CIPHER, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material =
            Vec::with_capacity(CIPHER_SZ + CIPHER_SZ + SECRET_SZ + SECRET_SZ + SIGNATURE_SZ);
        hashing_material.extend_from_slice(&self.stable_cipher);
        hashing_material.extend_from_slice(&self.session_cipher);
        hashing_material.extend_from_slice(&self.stable_secret);
        hashing_material.extend_from_slice(&self.session_secret);
        hashing_material.extend_from_slice(&self.signature);
        hashing_material
    }
}

impl AloecryptHashable for CounterPartySECRET {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_COUNTER_PARTY_SECRET, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(SECRET_SZ + SECRET_SZ + SIGNATURE_SZ);
        hashing_material.extend_from_slice(&self.stable_secret);
        hashing_material.extend_from_slice(&self.session_secret);
        hashing_material.extend_from_slice(&self.signature);
        hashing_material
    }
}

impl AloecryptHashable for PartyCHALLENGE {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY_CHALLENGE, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(ENCRYPTED_NONCE_SZ + ENCRYPTED_NONCE_SZ);
        hashing_material.extend_from_slice(&self.encrypted_challenge);
        hashing_material.extend_from_slice(&self.encrypted_check);
        hashing_material
    }
}

impl AloecryptHashable for PartyRESPONSE {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY_RESPONSE, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(SESSION_NONCE_SZ);
        hashing_material.extend_from_slice(&self.decrypted_challenge);
        hashing_material
    }
}

impl AloecryptHashable for CounterPartyCHALLENGE {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_COUNTER_PARTY_CHALLENGE, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(SESSION_NONCE_SZ + SESSION_NONCE_SZ);
        hashing_material.extend_from_slice(&self.decrypted_challenge);
        hashing_material.extend_from_slice(&self.decrypted_check);
        hashing_material
    }
}

impl AloecryptHashable for FromSecretsInput {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_FROM_SECRETS_INPUT, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        // Usually we look for the minimum unique set, but since this input is use to support custom sessions we hash everything
        let mut hashing_material = Vec::with_capacity(
            SECRET_SZ
                + SECRET_SZ
                + SIGNATURE_SZ
                + SESSION_NONCE_SZ
                + ADDRESS_SZ
                + SECRET_SZ
                + SECRET_SZ
                + SIGNATURE_SZ
                + SESSION_NONCE_SZ
                + ADDRESS_SZ
                + SESSION_SALT_SZ,
        );
        hashing_material.extend_from_slice(&self.stable_secret_a);
        hashing_material.extend_from_slice(&self.session_secret_a);
        hashing_material.extend_from_slice(&self.signature_a);
        hashing_material.extend_from_slice(&self.nonce_a);
        hashing_material.extend_from_slice(&self.address_a);
        hashing_material.extend_from_slice(&self.stable_secret_b);
        hashing_material.extend_from_slice(&self.session_secret_b);
        hashing_material.extend_from_slice(&self.signature_b);
        hashing_material.extend_from_slice(&self.nonce_b);
        hashing_material.extend_from_slice(&self.address_b);
        hashing_material.extend_from_slice(&self.session_salt);
        hashing_material
    }
}

impl AloecryptHashable for SessionBuilder {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_SESSION_BUILDER, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material =
            Vec::with_capacity(HASH_SZ + HASH_SZ + HASH_SZ + SESSION_NONCE_SZ + SESSION_NONCE_SZ);
        hashing_material.extend_from_slice(&self.delegate_signer.hash());
        hashing_material.extend_from_slice(&self.stable_kem.hash());
        hashing_material.extend_from_slice(&self.session_kem.hash());
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material.extend_from_slice(&self.challenge_nonce);
        hashing_material
    }
}

impl AloecryptHashable for MsgHELLO {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_MSG_HELLO, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + ADDRESS_SZ);
        hashing_material.extend_from_slice(&self.address);
        hashing_material.extend_from_slice(&self.intro.hash());
        hashing_material
    }
}

impl AloecryptHashable for MsgSYN {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_MSG_SYN, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + HASH_SZ);
        hashing_material.extend_from_slice(&self.intro.hash());
        hashing_material.extend_from_slice(&self.cipher.hash());
        hashing_material
    }
}

impl AloecryptHashable for MsgACK {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_MSG_ACK, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + HASH_SZ);
        hashing_material.extend_from_slice(&self.cipher.hash());
        hashing_material.extend_from_slice(&self.challenge.hash());
        hashing_material
    }
}

impl AloecryptHashable for MsgSYNACK {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_MSG_SYNACK, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + HASH_SZ);
        hashing_material.extend_from_slice(&self.challenge.hash());
        hashing_material.extend_from_slice(&self.challenge_response.hash());
        hashing_material
    }
}

impl AloecryptHashable for MsgWELCOME {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_MSG_WELCOME, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        self.challenge_response.hash().to_vec()
    }
}

impl AloecryptHashable for Party {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_PARTY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            SESSION_NONCE_SZ + SIGNATURE_SZ + HASH_SZ + HASH_SZ + SECRET_SZ + SECRET_SZ,
        );
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material.extend_from_slice(&self.session_signature);
        hashing_material.extend_from_slice(&self.delegate_signer.hash());
        hashing_material.extend_from_slice(&self.stable_kem.hash());
        hashing_material.extend_from_slice(&self.session_kem.hash());
        hashing_material.extend_from_slice(&self.stable_secret);
        hashing_material.extend_from_slice(&self.session_secret);
        hashing_material
    }
}

impl AloecryptHashable for CounterParty {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_COUNTER_PARTY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            ADDRESS_SZ
                + SESSION_NONCE_SZ
                + SIGNATURE_SZ
                + HASH_SZ
                + HASH_SZ
                + SECRET_SZ
                + SECRET_SZ,
        );
        hashing_material.extend_from_slice(&self.address);
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material.extend_from_slice(&self.signature);
        hashing_material.extend_from_slice(&self.stable_kem.hash());
        hashing_material.extend_from_slice(&self.session_kem.hash());
        hashing_material.extend_from_slice(&self.verifier.hash());
        hashing_material.extend_from_slice(&self.stable_secret);
        hashing_material.extend_from_slice(&self.session_secret);
        hashing_material
    }
}

impl AloecryptHashable for AloecryptSession {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_SESSION, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(SESSION_SALT_SZ + HASH_SZ + HASH_SZ);
        hashing_material.extend_from_slice(&self.party.hash());
        hashing_material.extend_from_slice(&self.counter_party.hash());
        hashing_material.extend_from_slice(&self.session_salt);
        hashing_material
    }
}

impl AloecryptSession {
    /// Hash of the private material within the session (party secrets, session salt, KEMs).
    /// Used for integrity verification when loading from password-protected PEM.
    pub fn priv_hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_SESSION_PRIV, self.priv_hashing_material())
    }
    fn priv_hashing_material(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(SECRET_SZ * 4 + SESSION_SALT_SZ + HASH_SZ + HASH_SZ);
        m.extend_from_slice(&self.party.stable_secret);
        m.extend_from_slice(&self.party.session_secret);
        m.extend_from_slice(&self.counter_party.stable_secret);
        m.extend_from_slice(&self.counter_party.session_secret);
        m.extend_from_slice(&self.session_salt);
        m.extend_from_slice(&self.party.delegate_signer.priv_hash());
        m.extend_from_slice(&self.party.stable_kem.priv_hash());
        m.extend_from_slice(&self.party.session_kem.priv_hash());
        m
    }
}

impl AloecryptXHashable for XAloecryptSession {
    fn hash(&self) -> AloecryptHash {
        self.un_hash
    }
    fn x_hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_X_SESSION, self.x_hashing_material())
    }
    fn x_hashing_material(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(HASH_SZ + HASH_SZ);
        m.extend_from_slice(&self.un_hash);
        m.extend_from_slice(&self.priv_hash);
        m
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
