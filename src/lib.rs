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
pub mod aloecrypt;
pub mod cli;
pub mod curve_convert;
pub mod error;
pub mod keyfile;
pub mod keypair;
pub mod peer_key;

pub const KEY_ITERS: u32 = 4096;
pub const COM_STRUCT_ID: &str = "AloeBuffer.0";
pub const MAGIC_BYTES: [u8; 16] = [
    0x41, 0x4c, 0x4f, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x69, 0x61, 0x6d, 0x6d, 0x69, 0x6b, 0x65,
];

use chacha20poly1305::Key as ChaChaKey;
use ed25519_dalek::Signature;
use error::AloecryptError;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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
    fn sign(&self, d: &[u8]) -> Signature;
}

pub trait PeerKey {}
