// src/lib.rs
// License: Apache-2.0 (disclaimer at bottom of file)
pub mod consts;
pub mod error;
pub mod kem;
pub mod macros;
pub mod option_big_array;
pub mod password;
pub mod session;
pub mod signatory;
pub mod time;
pub mod util;

pub use consts::*;
pub use error::*;
pub use kem::*;
pub use session::*;
pub use signatory::*;
pub use types::*;
pub use util::*;

include!(concat!(env!("OUT_DIR"), "/api.rs"));

use builder_api::*;
use kem_api::*;
use session_api::*;
use signatory_api::*;

pub fn aloecrypt_version() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"),)
}

// Crypto-safe RNG trait
pub trait CryptoRngCore: RngCore + CryptoRng {}
impl<T: RngCore + CryptoRng> CryptoRngCore for T {}

use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fmt::Write;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};
use hkdf::{Hkdf, HkdfExtract};
use pbkdf2::pbkdf2_hmac;

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    ExpandedSigningKey, ExpandedSigningKeyBytes, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature,
    SigningKey, VerifyingKey,
};
use ml_kem::{
    B32, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, ExpandedKeyEncoding,
    KeyExport, MlKem768, SharedKey, array::Array,
};

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
