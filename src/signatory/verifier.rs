// src/signatory/verifier.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct DilithiumVerifier {
    #[serde(with = "BigArray")]
    pub dlt_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_generation: u64,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
}

impl AloecryptVerifier for DilithiumVerifier {
    fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        VerifyingKey::decode((&self.dlt_pubkey).into())
    }
    fn may_verify(&self) -> bool {
        let now = _ts_bytes_now();
        now > self.dlt_active_from
    }
}

impl From<DilithiumSigner> for DilithiumVerifier {
    fn from(signer: DilithiumSigner) -> DilithiumVerifier {
        DilithiumVerifier {
            dlt_pubkey: signer.dlt_pubkey,
            dlt_sig_bytes: signer.dlt_sig_bytes,
            dlt_auth_pubkey: signer.dlt_auth_pubkey,
            dlt_root_pubkey: signer.dlt_root_pubkey,
            dlt_root_address: signer.dlt_root_address,
            dlt_auth_address: signer.dlt_auth_address,
            dlt_generation: signer.dlt_generation,
            dlt_created_at: signer.dlt_created_at,
            dlt_active_from: signer.dlt_active_from,
            dlt_expires_at: signer.dlt_expires_at,
            dlt_refresh_count: signer.dlt_refresh_count,
            dlt_max_refresh: signer.dlt_max_refresh,
        }
    }
}

impl From<XDilithiumSigner> for DilithiumVerifier {
    fn from(signer: XDilithiumSigner) -> DilithiumVerifier {
        DilithiumVerifier {
            dlt_pubkey: signer.dlt_pubkey,
            dlt_sig_bytes: signer.dlt_sig_bytes,
            dlt_auth_pubkey: signer.dlt_auth_pubkey,
            dlt_root_pubkey: signer.dlt_root_pubkey,
            dlt_root_address: signer.dlt_root_address,
            dlt_auth_address: signer.dlt_auth_address,
            dlt_generation: signer.dlt_generation,
            dlt_created_at: signer.dlt_created_at,
            dlt_active_from: signer.dlt_active_from,
            dlt_expires_at: signer.dlt_expires_at,
            dlt_refresh_count: signer.dlt_refresh_count,
            dlt_max_refresh: signer.dlt_max_refresh,
        }
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
