// src/session/util.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;

pub fn make_chacha_nonce(nonce_info_tag: &[u8], nonce_seed: String, salt: &[u8]) -> ChachaNonce {
    let mut chacha_nonce = EMPTY_CRYPT_NONCE;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &nonce_seed.as_bytes());
    hk.expand(&nonce_info_tag.as_bytes(), &mut chacha_nonce)
        .expect("12 bytes is a valid length");
    chacha_nonce
}

pub fn nonce_pair(
    session_salt: &AloecryptSessionSalt,
    session_seed: &str,
    stable_seed: &str,
) -> (ChachaNonce, ChachaNonce) {
    let session_nonce_bytes = make_chacha_nonce(
        SESSION_CHACHA_NONCE_INFO.as_bytes(),
        session_seed.to_string(),
        session_salt,
    );

    let stable_nonce_bytes = make_chacha_nonce(
        STABLE_CHACHA_NONCE_INFO.as_bytes(),
        stable_seed.to_string(),
        session_salt,
    );
    (session_nonce_bytes, stable_nonce_bytes)
}

pub fn cipher_pair(
    sender_salt: &[u8],
    sender_secret: &AloecryptSecret,
    receiver_salt: &[u8],
    receiver_secret: &AloecryptSecret,
) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
    let session_cipher = make_cipher(
        SESSION_CHACHA_KEY_INFO.as_bytes(),
        sender_salt,
        *sender_secret,
    );

    let stable_cipher = make_cipher(
        STABLE_CHACHA_KEY_INFO.as_bytes(),
        receiver_salt,
        *receiver_secret,
    );
    (session_cipher, stable_cipher)
}

pub fn make_cipher(key_info_tag: &[u8], salt: &[u8], secret: AloecryptSecret) -> ChaCha20Poly1305 {
    let mut chacha_key = EMPTY_CRYPT_KEY;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &secret);
    hk.expand(&key_info_tag.as_bytes(), &mut chacha_key)
        .expect("32 bytes is a valid length");
    ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key))
}

pub fn session_salt(
    n1: AloecryptSessionNonce,
    n2: AloecryptSessionNonce,
    a1: AloecryptAddress,
    a2: AloecryptAddress,
) -> AloecryptSessionSalt {
    let min_n = std::cmp::min(n1, n2);
    let max_n = std::cmp::max(n1, n2);
    let min_a = std::cmp::min(a1, a2);
    let max_a = std::cmp::max(a1, a2);

    let mut payload1 = Vec::new();
    let mut payload2 = Vec::new();
    payload1.extend_from_slice(&min_n);
    payload1.extend_from_slice(&max_n);
    payload2.extend_from_slice(&min_a);
    payload2.extend_from_slice(&max_a);

    let mut session_salt = [0u8; 32];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&payload1), &payload2);
    hk.expand(&SESSION_SALT_INFO, &mut session_salt)
        .expect("32 bytes is a valid length");
    session_salt
}

pub fn cipher_salt(
    seed: &[u8],
    session_salt: &AloecryptSessionSalt,
    decryptor_nonce: &AloecryptSessionNonce,
    encryptor_nonce: &AloecryptSessionNonce,
    encryptor_address: &AloecryptAddress,
) -> AloecryptSessionSalt {
    let mut salt_material: Vec<u8> =
        Vec::with_capacity(SESSION_NONCE_SZ + SESSION_SALT_SZ + ADDRESS_SZ);
    salt_material.extend_from_slice(session_salt);
    salt_material.extend_from_slice(encryptor_nonce);
    salt_material.extend_from_slice(encryptor_address);

    let mut cipher_salt = EMPTY_SESSION_SALT;
    hkdf::Hkdf::<sha2::Sha256>::new(Some(decryptor_nonce), &seed)
        .expand(&salt_material.as_bytes(), &mut cipher_salt)
        .expect("32 bytes is a valid length");
    cipher_salt
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
