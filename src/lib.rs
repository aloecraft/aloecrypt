// src/lib.rs
// License: Apache-2.0 (disclaimer at bottom of file)
pub mod consts;
pub mod crypt;
pub mod error;
pub mod kem;
pub mod macros;
pub mod session;
pub mod signatory;
pub mod time;
pub mod traits;
pub mod types;
pub mod util;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Error, Key as ChaChaKey, Nonce};
use error::AloecryptError;
use getrandom;
use hkdf::{Hkdf, HkdfExtract};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{KeyGen, KeyPair, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{
    B32, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, ExpandedKeyEncoding,
    KeyExport, MlKem768, SharedKey, array::Array,
};
use pbkdf2::pbkdf2_hmac;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore as SysRng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_core::TryRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fmt::Write;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zerocopy::IntoBytes;

pub trait KeyPEM {
    fn pem(&self) -> String;
    fn loads(pem: &str) -> Result<Self, AloecryptError>
    where
        Self: Sized;
}

pub trait PubKey {
    fn x_pubkey(&self) -> Result<X25519PublicKey, AloecryptError>;
    fn send_encrypt(
        &self,
        my_privkey: &StaticSecret,
        d: &[u8],
        peer_nonce: &[u8],
    ) -> Result<Vec<u8>, AloecryptError>;
    fn recv_decrypt(
        &self,
        my_privkey: &StaticSecret,
        d: &[u8],
        peer_nonce: &[u8],
    ) -> Result<Vec<u8>, AloecryptError>;
    fn verify(&self, sig_bytes: &[u8; 64], d: &[u8]) -> bool;
}

pub trait PrivKey {
    fn x_privkey(&self) -> StaticSecret;
    fn self_encrypt(&self, d: &[u8]) -> Result<Vec<u8>, AloecryptError>;
    fn self_decrypt(&self, d: &[u8]) -> Result<Vec<u8>, AloecryptError>;
    fn derive_chacha_key(&self) -> Result<ChaChaKey, AloecryptError>;
    fn sign(&self, d: &[u8]) -> Signature<MlDsa65>;
}

pub trait PeerKey {}

pub mod option_big_array {

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_big_array::BigArray;

    use crate::option_big_array;

    pub fn serialize<S, const N: usize>(val: &Option<[u8; N]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(arr) => s.serialize_some(&serde_bytes::Bytes::new(arr)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(buf) => {
                let arr: [u8; N] = buf.into_vec().try_into().map_err(|_| {
                    serde::de::Error::custom(format!("expected byte array of length {}", N))
                })?;
                Ok(Some(arr))
            }
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
