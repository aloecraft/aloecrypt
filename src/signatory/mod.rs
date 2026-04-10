// src/signatory/mod.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::error::AloecryptError;
use crate::kem::*;
use crate::option_big_array;
use crate::password::*;
use crate::traits::*;
use crate::types::*;
use crate::util::*;

pub mod addressable;
pub mod empty;
pub mod hashable;
pub mod into;
pub mod jwt;
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
pub use into::*;
pub use jwt::*;
pub use password::*;
pub use password_pem::*;
pub use pem::*;
pub use signable::*;
pub use signature::*;
pub use signer::*;
pub use verifier::*;

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
