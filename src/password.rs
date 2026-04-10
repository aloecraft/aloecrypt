// src/password.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::error::*;
use crate::traits::*;

pub fn password_encrypt(
    bytes: &[u8],
    aad: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: &ChachaNonce,
) -> Result<Vec<u8>, AloecryptError> {
    let mut chacha_key = EMPTY_CRYPT_KEY;
    pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let payload = Payload {
        msg: bytes,
        aad: aad,
    };

    let encrypted = cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AloecryptError::PasswordEncrypt)?;
    Ok(encrypted)
}

pub fn password_decrypt(
    bytes: &[u8],
    aad: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: &ChachaNonce,
) -> Result<Vec<u8>, AloecryptError> {
    let mut chacha_key = EMPTY_CRYPT_KEY;
    pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let payload = Payload {
        msg: bytes,
        aad: aad,
    };
    let encrypted = cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|e| AloecryptError::PasswordDecrypt)?;
    Ok(encrypted)
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
