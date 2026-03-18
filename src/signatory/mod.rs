// src/signatory/mod.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::error::AloecryptError;
use crate::kem::*;
use crate::option_big_array;
use crate::time::{SystemTime, UNIX_EPOCH};
use crate::traits::*;
use crate::types::*;
use crate::util::*;

pub mod addressable;
pub mod empty;
pub mod hashable;
pub mod jwt;
pub mod keys;
pub mod password;
pub mod password_pem;
pub mod pem;
pub mod signable;
pub mod signature;
pub mod signer;
pub mod verifier;

pub use addressable::*;
pub use empty::*;
pub use hashable::*;
pub use jwt::*;
pub use password::*;
pub use password_pem::*;
pub use pem::*;
pub use signable::*;
pub use signature::*;
pub use signer::*;
pub use verifier::*;

const SIGNER_PEM_TAG: &str = "Aloecrypt DilithiumSigner";
const VERIFIER_PEM_TAG: &str = "Aloecrypt DilithiumVerifier";
const SIGNATURE_PEM_TAG: &str = "Aloecrypt DilithiumSignature";

fn _ts_bytes_now() -> [u8; 8] {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms.to_le_bytes()
} // Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
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
