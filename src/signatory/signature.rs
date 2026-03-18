// src/signatory/signature.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

pub type DilithiumSignature = [u8; SIGNATURE_SZ];

pub struct Authorization {
    address: AloecryptAddress,
    signature: DilithiumSignature,
    auth_by_address: AloecryptAddress,
    auth_by_generation: u64,

    generation: u64,
    from: Timestamp,
    until: Timestamp,
    refresh_remaining: u64,
}

// {"typ":"JWT",
//  "alg":"ML-DSA-65"}

pub struct AuthorizationChainEntry {}
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
