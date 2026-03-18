// src/signatory/signable.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptSignable for DilithiumSigner {
    fn signature(&self) -> DilithiumSignature {
        self.dlt_sig_bytes
    }
    fn signed_by(&self) -> AloecryptAddress {
        self.dlt_auth_address
    }
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(HASH_SZ);
        signing_material.extend_from_slice(&self.hash());
        signing_material
    }
}

impl AloecryptSignable for DilithiumVerifier {
    fn signature(&self) -> DilithiumSignature {
        self.dlt_sig_bytes
    }
    fn signed_by(&self) -> AloecryptAddress {
        self.dlt_auth_address
    }
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(HASH_SZ);
        signing_material.extend_from_slice(&self.hash());
        signing_material
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
