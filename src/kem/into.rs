// src/kem/full.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::password::*;

impl Into<KyberPublicKEM> for KyberFullKEM {
    fn into(self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.dlt_auth_address,
            dlt_root_address: self.dlt_root_address,
            dlt_generation: self.dlt_generation,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
        }
    }
}

impl Into<KyberPublicKEM> for XKyberFullKEM {
    fn into(self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.dlt_auth_address,
            dlt_root_address: self.dlt_root_address,
            dlt_generation: self.dlt_generation,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
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
