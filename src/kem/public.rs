// src/kem/public.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct KyberPublicKEM {
    #[serde(with = "BigArray")]
    pub kyb_pubkey: KyberPubkey,
    #[serde(with = "BigArray")]
    pub kyb_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
    pub dlt_generation: u64,
}

impl AloecryptEncapsulator for KyberPublicKEM {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        EncapsulationKey::<MlKem768>::new(&(self.kyb_pubkey).into()).unwrap()
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
