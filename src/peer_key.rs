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
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pbkdf2::pbkdf2_hmac;
use std::fmt::Write;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::{KeyPEM, PubKey};
use crate::curve_convert::to_curve25519_public_key;
use crate::error::AloecryptError;

// Make sure these are accessible from wherever you place this file
use crate::{COM_STRUCT_ID, KEY_ITERS};

// Define the trait with the expected operations
#[derive(Debug, Clone)]
pub struct PeerKey {
    pub cid: [u8; 16],
    pub public_key: [u8; 32],
}

impl KeyPEM for PeerKey {
    fn pem(&self) -> String {
        let mut pem_bytes = Vec::with_capacity(16 + 32);
        pem_bytes.extend_from_slice(&self.cid);
        pem_bytes.extend_from_slice(&self.public_key);

        let mut out = String::from("-----BEGIN ALOECRYPT PEERKEY-----\n");
        for chunk in pem_bytes.chunks(32) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str("-----END ALOECRYPT PEERKEY-----\n");
        out
    }

    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();

        let header = "-----BEGIN ALOECRYPT PEERKEY-----";
        let footer = "-----END ALOECRYPT PEERKEY-----";

        if !stripped.starts_with(header) || !stripped.ends_with(footer) {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let hex_body = &stripped[header.len()..stripped.len() - footer.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;

        // Ensure the byte length is exactly 16 (cid) + 32 (pub) = 48 bytes
        if bytes.len() != 48 {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let mut cid = [0u8; 16];
        cid.copy_from_slice(&bytes[0..16]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[16..48]);

        Ok(Self { cid, public_key })
    }
}

impl PubKey for PeerKey {
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

#[cfg(test)]
mod peerkey_tests {
    use super::*;

    #[test]
    fn test_peerkey_pem_roundtrip() {
        let original_peer = PeerKey {
            cid: [0xAA; 16],
            public_key: [0xBB; 32],
        };

        let pem_string = original_peer.pem();
        let loaded_peer = PeerKey::loads(&pem_string).expect("Should parse valid PEM");

        assert_eq!(original_peer.cid, loaded_peer.cid);
        assert_eq!(original_peer.public_key, loaded_peer.public_key);
    }
}
