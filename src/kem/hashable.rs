// src/kem/hashable.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptHashable for KyberPubkey {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_KYB_PUBKEY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl AloecryptHashable for KyberPrivkey {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_KYB_PRIVKEY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl AloecryptXHashable for XKyberFullKEM {
    fn hash(&self) -> AloecryptHash {
        self.un_hash
    }
    fn x_hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_KYB_X_FULLKEM, self.x_hashing_material())
    }
    fn x_hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + HASH_SZ + CHACHA_NONCE_SZ);
        hashing_material.extend_from_slice(&self.kyb_priv_hash);
        hashing_material.extend_from_slice(&self.un_hash);
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material
    }
}

impl AloecryptHashable for KyberPublicKEM {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_KYB_PUBKEM, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            HASH_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + U32_SZ
                + U32_SZ
                + U64_SZ,
        );
        hashing_material.extend_from_slice(&self.pub_hash());
        hashing_material.extend_from_slice(&self.address());
        hashing_material.extend_from_slice(&self.dlt_auth_address);
        hashing_material.extend_from_slice(&self.dlt_root_address);
        hashing_material.extend_from_slice(&self.dlt_created_at);
        hashing_material.extend_from_slice(&self.dlt_active_from);
        hashing_material.extend_from_slice(&self.dlt_expires_at);
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        hashing_material.extend_from_slice(&u64::to_le_bytes(self.generation()));
        hashing_material
    }
}

impl AloecryptHashable for KyberFullKEM {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_KYB_PUBKEM, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            HASH_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + U32_SZ
                + U32_SZ
                + U64_SZ,
        );
        hashing_material.extend_from_slice(&self.pub_hash());
        hashing_material.extend_from_slice(&self.address());
        hashing_material.extend_from_slice(&self.dlt_auth_address);
        hashing_material.extend_from_slice(&self.dlt_root_address);
        hashing_material.extend_from_slice(&self.dlt_created_at);
        hashing_material.extend_from_slice(&self.dlt_active_from);
        hashing_material.extend_from_slice(&self.dlt_expires_at);
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        hashing_material.extend_from_slice(&u64::to_le_bytes(self.generation()));
        hashing_material
    }
}

impl AloecryptHashableKeypair for KyberFullKEM {
    fn pub_hash(&self) -> AloecryptHash {
        self.kyb_pubkey.hash()
    }
    fn priv_hash(&self) -> AloecryptHash {
        self.kyb_privkey.hash()
    }
}

impl AloecryptHashableKeypair for XKyberFullKEM {
    fn pub_hash(&self) -> AloecryptHash {
        self.kyb_pubkey.hash()
    }
    fn priv_hash(&self) -> AloecryptHash {
        self.kyb_priv_hash
    }
}

impl AloecryptHashablePubkey for KyberPublicKEM {
    fn pub_hash(&self) -> AloecryptHash {
        self.kyb_pubkey.hash()
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
