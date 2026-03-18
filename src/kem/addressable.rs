// src/kem/addressable.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::util::_address;

impl AloecryptAddressable for XKyberFullKEM {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_auth_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_pubkey b/c address is always tied to delegate signer
}

impl AloecryptAddressable for KyberFullKEM {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_auth_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_pubkey b/c address is always tied to delegate signer
}

impl AloecryptAddressable for KyberPublicKEM {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_auth_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_pubkey b/c address is always tied to delegate signer
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
