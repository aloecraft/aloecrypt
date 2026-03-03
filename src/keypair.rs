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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pbkdf2::pbkdf2_hmac;
use rand_core::OsRng;
use std::fmt::Write;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::{KeyPEM, PrivKey, PubKey};
use crate::curve_convert::{to_curve25519_private_key, to_curve25519_public_key};
use crate::error::AloecryptError;

use crate::{COM_STRUCT_ID, KEY_ITERS};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub cid: [u8; 16],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl KeyPEM for Keypair {
    /// Formats the keypair into the custom ALOECRYPT PEM string.
    fn pem(&self) -> String {
        let mut pem_bytes = Vec::with_capacity(16 + 32 + 32);
        pem_bytes.extend_from_slice(&self.cid);
        pem_bytes.extend_from_slice(&self.private_key);
        pem_bytes.extend_from_slice(&self.public_key);

        let mut out = String::from("-----BEGIN ALOECRYPT ver.1-----\n");
        for chunk in pem_bytes.chunks(32) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str("-----END ALOECRYPT ver.1-----\n");
        out
    }

    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        // Strip all newlines and whitespace just like the Python list comprehension
        let stripped: String = pem.lines().map(|l| l.trim()).collect();

        let header = "-----BEGIN ALOECRYPT ver.1-----";
        let footer = "-----END ALOECRYPT ver.1-----";

        if !stripped.starts_with(header) || !stripped.ends_with(footer) {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let hex_body = &stripped[header.len()..stripped.len() - footer.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;

        // Ensure the byte length is exactly 16 (cid) + 32 (priv) + 32 (pub) = 80 bytes
        if bytes.len() != 80 {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let mut cid = [0u8; 16];
        cid.copy_from_slice(&bytes[0..16]);

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes[16..48]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[48..80]);

        Ok(Self {
            cid,
            private_key,
            public_key,
        })
    }
}

impl PrivKey for Keypair {
    fn x_privkey(&self) -> StaticSecret {
        let x_priv_bytes = to_curve25519_private_key(&self.private_key);
        StaticSecret::from(x_priv_bytes)
    }
    fn self_encrypt(&self, d: &[u8]) -> Result<Vec<u8>, AloecryptError> {
        let key = self.derive_chacha_key()?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
        let payload = Payload {
            msg: d,
            aad: &self.cid,
        };

        // The ? operator perfectly handles the conversion via our From impl
        Ok(cipher.encrypt(nonce, payload)?)
    }

    fn self_decrypt(&self, d: &[u8]) -> Result<Vec<u8>, AloecryptError> {
        let key = self.derive_chacha_key()?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
        let payload = Payload {
            msg: d,
            aad: &self.cid,
        };

        // The ? operator perfectly handles the conversion via our From impl
        Ok(cipher.decrypt(nonce, payload)?)
    }

    /// Helper function to derive the ChaCha20 key via PBKDF2-HMAC-SHA256
    fn derive_chacha_key(&self) -> Result<ChaChaKey, AloecryptError> {
        let x_priv = self.x_privkey();
        let x_pub = self.x_pubkey()?;

        let shared_secret = x_priv.diffie_hellman(&x_pub);

        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha512>(
            shared_secret.as_bytes(),
            &self.cid,
            KEY_ITERS,
            &mut chacha_key,
        );

        Ok(ChaChaKey::from(chacha_key))
    }

    fn sign(&self, d: &[u8]) -> Signature {
        let signing_key = SigningKey::from_bytes(&self.private_key);
        signing_key.sign(d)
    }
}

impl PubKey for Keypair {
    fn x_pubkey(&self) -> Result<X25519PublicKey, AloecryptError> {
        let x_pub_bytes = to_curve25519_public_key(&self.public_key)?;
        Ok(X25519PublicKey::from(x_pub_bytes))
    }

    fn send_encrypt(
        &self,
        my_privkey: &StaticSecret,
        d: &[u8],
        peer_nonce: &[u8],
    ) -> Result<Vec<u8>, AloecryptError> {
        let x_pub = self.x_pubkey()?;
        let shared_secret = my_privkey.diffie_hellman(&x_pub);

        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(
            shared_secret.as_bytes(),
            peer_nonce,
            KEY_ITERS,
            &mut chacha_key,
        );

        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
        let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
        let payload = Payload {
            msg: d,
            aad: peer_nonce,
        };

        Ok(cipher.encrypt(nonce, payload)?)
    }

    fn recv_decrypt(
        &self,
        my_privkey: &StaticSecret,
        d: &[u8],
        peer_nonce: &[u8],
    ) -> Result<Vec<u8>, AloecryptError> {
        let x_pub = self.x_pubkey()?;
        let shared_secret = my_privkey.diffie_hellman(&x_pub);

        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(
            shared_secret.as_bytes(),
            peer_nonce,
            KEY_ITERS,
            &mut chacha_key,
        );

        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
        let nonce = Nonce::from_slice(COM_STRUCT_ID.as_bytes());
        let payload = Payload {
            msg: d,
            aad: peer_nonce,
        };

        Ok(cipher.decrypt(nonce, payload)?)
    }

    fn verify(&self, sig_bytes: &[u8; 64], d: &[u8]) -> bool {
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&self.public_key) {
            let signature = Signature::from_bytes(sig_bytes);
            return verifying_key.verify(d, &signature).is_ok();
        }
        false
    }
}

impl Keypair {
    /// Generates a new Ed25519 keypair and assigns a UUIDv7 CID.
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        Self {
            cid: Uuid::now_v7().into_bytes(),
            private_key: signing_key.to_bytes(),
            public_key: signing_key.verifying_key().to_bytes(),
        }
    }
}

#[cfg(test)]
mod keypair_tests {
    use super::*;

    #[test]
    fn test_keypair_generation_and_pem_format() {
        let kp = Keypair::new();
        let pem = kp.pem();

        assert!(pem.starts_with("-----BEGIN ALOECRYPT ver.1-----\n"));
        assert!(pem.ends_with("-----END ALOECRYPT ver.1-----\n"));

        // CID + Private + Public = 16 + 32 + 32 = 80 bytes.
        // Hex encoded, that's 160 characters, plus newlines.
        assert!(pem.len() > 160);
    }

    #[test]
    fn test_self_encrypt_decrypt_roundtrip() {
        let kp = Keypair::new();
        let original_data = b"confidential payload data";

        // 1. Encrypt the data
        let ciphertext = kp
            .self_encrypt(original_data)
            .expect("Encryption should succeed with a valid keypair");

        // Ensure it actually transformed the data
        assert_ne!(original_data.as_slice(), ciphertext.as_slice());

        // 2. Decrypt the data
        let decrypted_data = kp
            .self_decrypt(&ciphertext)
            .expect("Decryption should succeed with the same keypair");

        // 3. Verify it matches the original
        assert_eq!(original_data.as_slice(), decrypted_data.as_slice());
    }

    #[test]
    fn test_self_decrypt_tampered_ciphertext() {
        let kp = Keypair::new();
        let original_data = b"sensitive information";

        let mut ciphertext = kp.self_encrypt(original_data).unwrap();

        // Tamper with the ciphertext (flip a bit in the last byte, which is part of the Poly1305 auth tag)
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 1;

        // Decryption must fail and bubble up our unified cipher error
        let result = kp.self_decrypt(&ciphertext);
        assert!(matches!(result, Err(AloecryptError::Cipher(_))));
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = Keypair::new();
        let message = b"authorize transaction 12345";

        // Generate the signature
        let signature = kp.sign(message);
        let sig_bytes = signature.to_bytes();

        // Verify with the correct message
        assert!(kp.verify(&sig_bytes, message));

        // Ensure verification fails on a tampered message
        let tampered_message = b"authorize transaction 99999";
        assert!(!kp.verify(&sig_bytes, tampered_message));

        // Ensure verification fails on a tampered signature
        let mut bad_sig_bytes = sig_bytes;
        bad_sig_bytes[0] ^= 1;
        assert!(!kp.verify(&bad_sig_bytes, message));
    }

    #[test]
    fn test_keypair_pem_roundtrip() {
        let original_kp = Keypair::new();
        let pem_string = original_kp.pem();

        let loaded_kp = Keypair::loads(&pem_string).expect("Should parse valid PEM");

        assert_eq!(original_kp.cid, loaded_kp.cid);
        assert_eq!(original_kp.private_key, loaded_kp.private_key);
        assert_eq!(original_kp.public_key, loaded_kp.public_key);
    }
}
