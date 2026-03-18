// src/kem/mod.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::consts::*;
use super::traits::*;
use super::traits::*;
use super::*;
use crate::crypt::*;
use crate::error::AloecryptError;
use crate::option_big_array;
use crate::signatory::*;
use crate::types::*;
use crate::util::*;

pub mod cipher;
pub mod full;
pub mod public;

pub mod addressable;
pub mod empty;
pub mod hashable;
pub mod password_pem;
pub mod pem;
pub mod signable;

pub use cipher::*;
pub use full::*;
pub use public::*;

pub use addressable::*;
pub use empty::*;
pub use hashable::*;
pub use password_pem::*;
pub use pem::*;
pub use signable::*;

const KYBER_FULL_TAG: &str = "Aloecrypt KyberFullKEM";
const KYBER_PUBLIC_TAG: &str = "Aloecrypt KyberPublicKEM";
const CIPHER_PEM_TAG: &str = "Aloecrypt Cipher";
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
