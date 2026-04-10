// src/util.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use std::ops::Deref;

use super::*;
use crate::consts::*;
use crate::error::*;
use crate::time::{SystemTime, UNIX_EPOCH};
use crate::types::*;

pub fn _ts_bytes_now() -> Timestamp {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms.to_le_bytes()
}

pub fn _address(address_seed: &str, addressing_material: Vec<u8>) -> AloecryptAddress {
    let mut aloecrypt_address = EMPTY_ADDRESS;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &address_seed.as_bytes());
    hk.expand(&addressing_material, &mut aloecrypt_address)
        .expect("aloecrypt_address from addressing_material material");
    aloecrypt_address
}

pub fn _hash(hash_seed: &str, hashing_material: Vec<u8>) -> AloecryptHash {
    let mut aloecrypt_hash = EMPTY_HASH;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &hash_seed.as_bytes());
    hk.expand(&hashing_material, &mut aloecrypt_hash)
        .expect("aloecrypt_hash from hashing material");
    aloecrypt_hash
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
