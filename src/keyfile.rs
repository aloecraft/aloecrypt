// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
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
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
use pbkdf2::pbkdf2_hmac;
use std::fmt::Write;

use super::KeyPEM;
use crate::error::AloecryptError;
use crate::keypair::Keypair;
use crate::{COM_STRUCT_ID, KEY_ITERS};

#[derive(Debug, Clone)]
pub struct Keyfile {
    pub cid: [u8; 16],
    pub public_key: [u8; 32],
    pub inner: [u8; 48], // 32 bytes (private key) + 16 bytes (Poly1305 auth tag)
}

impl KeyPEM for Keyfile {
    fn pem(&self) -> String {
        // 16 (cid) + 48 (inner) + 32 (pub) = 96 bytes total
        let mut pem_bytes = Vec::with_capacity(96);
        pem_bytes.extend_from_slice(&self.cid);
        pem_bytes.extend_from_slice(&self.inner);
        pem_bytes.extend_from_slice(&self.public_key);

        let mut out = String::from("-----BEGIN ALOECRYPT KEYFILE-----\n");
        for chunk in pem_bytes.chunks(32) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str("-----END ALOECRYPT KEYFILE-----\n");
        out
    }

    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();

        let header = "-----BEGIN ALOECRYPT KEYFILE-----";
        let footer = "-----END ALOECRYPT KEYFILE-----";

        if !stripped.starts_with(header) || !stripped.ends_with(footer) {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let hex_body = &stripped[header.len()..stripped.len() - footer.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;

        // Validate exact length (16 + 48 + 32 = 96 bytes)
        if bytes.len() != 96 {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let mut cid = [0u8; 16];
        cid.copy_from_slice(&bytes[0..16]);

        let mut inner = [0u8; 48];
        inner.copy_from_slice(&bytes[16..64]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[64..96]);

        Ok(Self {
            cid,
            inner,
            public_key,
        })
    }
}

/// Encrypts a Keypair's private key using a password, returning a secure Keyfile.
pub fn key_pack(keypair: &Keypair, password: &[u8]) -> Result<Keyfile, AloecryptError> {
    let mut chacha_key = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(password, &keypair.cid, KEY_ITERS, &mut chacha_key);

    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
    let payload = Payload {
        msg: &keypair.private_key,
        aad: &keypair.cid,
    };

    // Encrypt the private key
    let encrypted = cipher.encrypt(nonce, payload)?;

    let mut inner = [0u8; 48];
    // A 32 byte private key + 16 byte MAC tag will always equal exactly 48 bytes
    if encrypted.len() == 48 {
        inner.copy_from_slice(&encrypted);
    } else {
        return Err(AloecryptError::InvalidPemFormat);
    }

    Ok(Keyfile {
        cid: keypair.cid,
        public_key: keypair.public_key,
        inner,
    })
}

/// Decrypts a Keyfile using a password to recover the original Keypair.
pub fn key_unpack(keyfile: &Keyfile, password: &[u8]) -> Result<Keypair, AloecryptError> {
    let mut chacha_key = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(password, &keyfile.cid, KEY_ITERS, &mut chacha_key);

    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
    let payload = Payload {
        msg: &keyfile.inner[..],
        aad: &keyfile.cid,
    };

    // Decrypt to recover the private key
    let decrypted = cipher.decrypt(nonce, payload)?;

    if decrypted.len() != 32 {
        return Err(AloecryptError::InvalidPemFormat);
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&decrypted);

    Ok(Keypair {
        cid: keyfile.cid,
        private_key,
        public_key: keyfile.public_key,
    })
}

#[cfg(test)]
mod keyfile_tests {
    use super::*;
    // Make sure Keypair is in scope, adjust path if necessary based on your crate structure
    use crate::keypair::Keypair;

    #[test]
    fn test_key_pack_unpack_roundtrip() {
        let original_kp = Keypair::new();
        let password = b"super_secure_passphrase_123";

        // 1. Pack the keypair into a keyfile
        let keyfile = key_pack(&original_kp, password)
            .expect("Packing should succeed with a valid keypair and password");

        // 2. Unpack the keyfile back into a keypair
        let unpacked_kp = key_unpack(&keyfile, password)
            .expect("Unpacking should succeed with the correct password");

        // 3. Verify the restored keypair perfectly matches the original
        assert_eq!(original_kp.cid, unpacked_kp.cid);
        assert_eq!(original_kp.private_key, unpacked_kp.private_key);
        assert_eq!(original_kp.public_key, unpacked_kp.public_key);
    }

    #[test]
    fn test_key_unpack_wrong_password() {
        let original_kp = Keypair::new();
        let correct_password = b"correct_password";
        let wrong_password = b"wrong_password";

        let keyfile = key_pack(&original_kp, correct_password).unwrap();

        // Attempt to unpack with the wrong password
        let result = key_unpack(&keyfile, wrong_password);

        // The ChaCha20Poly1305 MAC validation MUST fail here
        assert!(matches!(result, Err(AloecryptError::Cipher(_))));
    }

    #[test]
    fn test_keyfile_pem_roundtrip() {
        let original_kp = Keypair::new();
        let password = b"test_password";

        let original_keyfile = key_pack(&original_kp, password).unwrap();
        let pem_string = original_keyfile.pem();

        // Ensure formatting headers are correct
        assert!(pem_string.starts_with("-----BEGIN ALOECRYPT KEYFILE-----\n"));
        assert!(pem_string.ends_with("-----END ALOECRYPT KEYFILE-----\n"));

        // Deserialize the PEM string back into a Keyfile struct
        let loaded_keyfile =
            Keyfile::loads(&pem_string).expect("Should successfully parse a valid Keyfile PEM");

        // Verify the inner bytes match exactly
        assert_eq!(original_keyfile.cid, loaded_keyfile.cid);
        assert_eq!(original_keyfile.inner, loaded_keyfile.inner);
        assert_eq!(original_keyfile.public_key, loaded_keyfile.public_key);
    }
}
