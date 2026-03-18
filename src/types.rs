// src/types.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;

pub type DilithiumPubkey = [u8; VERIFY_KEY_SZ];
pub type DilithiumPrivkey = [u8; SIGN_KEY_SZ];
pub type XDilithiumPrivkey = [u8; SIGN_KEY_SZ + ENCRYPTED_TAG_SZ];
pub type KyberPubkey = [u8; ENCAPSULATE_KEY_SZ];
pub type KyberPrivkey = [u8; DECAPSULATE_KEY_SZ];
pub type XKyberPrivkey = [u8; DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ];
pub type AloecryptAddress = [u8; ADDRESS_SZ];
pub type AloecryptHash = [u8; HASH_SZ];
pub type AloecryptSecret = [u8; SECRET_SZ];
pub type XAloecryptSecret = [u8; SECRET_SZ + ENCRYPTED_TAG_SZ];
pub type AloecryptSessionNonce = [u8; SESSION_NONCE_SZ];
pub type AloecryptSessionSalt = [u8; SESSION_SALT_SZ];
pub type XAloecryptSessionSalt = [u8; SESSION_SALT_SZ + ENCRYPTED_TAG_SZ];
pub type Timestamp = [u8; TIMESTAMP_SZ]; // Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
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
