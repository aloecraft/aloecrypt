// src/signatory/signer.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptSigner for DilithiumSigner {
    fn signing_key(&self) -> DilithiumPrivSeed {
        self.dlt_privseed
    }
    fn may_sign(&self) -> bool {
        self.may_verify()
            && (self.dlt_expires_at == EMPTY_TIMESTAMP || _ts_bytes_now() < self.dlt_expires_at)
    }
    fn sign(&self, signing_material: Vec<u8>) -> DilithiumSignature {
        MlDsa65::from_seed((&self.dlt_privseed).into())
            .sign(signing_material.as_slice())
            .encode()
            .into()
    }
}

impl IDilithiumSigner for DilithiumSigner {
    fn new(mut rng: &mut dyn CryptoRngCore) -> Self {
        let dlt_created_at = _ts_bytes_now();
        let mut dsa_seed = EMPTY_SIGN_SEED;
        rng.fill_bytes(&mut dsa_seed);
        let keypair = MlDsa65::from_seed((&dsa_seed).into());
        let dlt_privkey = keypair.signing_key().to_expanded().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let dlt_active_from = EMPTY_TIMESTAMP;
        let dlt_expires_at = EMPTY_TIMESTAMP;
        let dlt_refresh_count = 0;
        let dlt_max_refresh = 0;
        let mut unsigned = Self {
            dlt_pubkey: dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_root_pubkey: dlt_pubkey,
            dlt_auth_pubkey: dlt_pubkey,
            dlt_privseed: dsa_seed,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_root_address: EMPTY_ADDRESS,
            dlt_auth_address: EMPTY_ADDRESS,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: 0u32,
            dlt_max_refresh: 0u32,
            dlt_generation: 0u64,
        };
        unsigned.dlt_root_address = unsigned.address();
        unsigned.dlt_auth_address = unsigned.address();
        unsigned.dlt_sig_bytes = unsigned.sign(unsigned.signing_material());
        unsigned
    }

    fn canonical_dilithium_signer(
        &self,
        cannonical_idx: &[u8],
        dlt_active_from: Timestamp,
        dlt_expires_at: Timestamp,
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> DilithiumSigner {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);
        let dlt_created_at = _ts_bytes_now();
        let mut dsa_seed = EMPTY_SIGN_SEED;
        pbkdf2_hmac::<sha2::Sha256>(&self.dlt_privkey, &cannonical_idx, KEY_ITERS, &mut dsa_seed);
        let keypair = MlDsa65::from_seed((&dsa_seed).into());
        let dlt_privkey = keypair.signing_key().to_expanded().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let mut unsigned = Self {
            dlt_pubkey: dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_privseed: dsa_seed,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_root_address: EMPTY_ADDRESS,
            dlt_auth_address: EMPTY_ADDRESS,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: 0u32,
            dlt_max_refresh: 0u32,
            dlt_generation: self.generation() + 1,
        };
        unsigned.dlt_root_address = self.root_address();
        unsigned.dlt_auth_address = self.address();
        unsigned.dlt_sig_bytes = self.sign(unsigned.signing_material());
        unsigned
    }

    fn create_dilithium_signer(
        &self,
        mut rng: &mut dyn CryptoRngCore,
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> Self {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);
        let dlt_created_at = _ts_bytes_now();

        let mut dsa_seed = EMPTY_SIGN_SEED;
        rng.fill_bytes(&mut dsa_seed);
        let keypair = MlDsa65::from_seed((&dsa_seed).into());
        let dlt_privkey = keypair.signing_key().to_expanded().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let mut unsigned = Self {
            dlt_pubkey: dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_privseed: dsa_seed,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_root_address: EMPTY_ADDRESS,
            dlt_auth_address: EMPTY_ADDRESS,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: 0u32,
            dlt_max_refresh: 0u32,
            dlt_generation: self.generation() + 1,
        };
        unsigned.dlt_root_address = self.root_address();
        unsigned.dlt_auth_address = self.address();
        unsigned.dlt_sig_bytes = self.sign(unsigned.signing_material());
        unsigned
    }

    fn canonical_kyber_kem(
        &self,
        cannonical_idx: &[u8],
        dlt_active_from: Timestamp,
        dlt_expires_at: Timestamp,
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> KyberFullKEM {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);
        let dlt_created_at = _ts_bytes_now();

        let mut kyber_seed = EMPTY_KYBER_SEED;
        pbkdf2_hmac::<sha2::Sha256>(
            &self.dlt_privkey,
            &cannonical_idx,
            KEY_ITERS,
            &mut kyber_seed,
        );
        let kyb_privkey = DecapsulationKey::<MlKem768>::from_seed(kyber_seed.into());
        let kyb_pubkey = kyb_privkey.encapsulation_key();

        let mut kyber_full_kem = KyberFullKEM {
            kyb_privkey: kyb_privkey.to_expanded_bytes().into(),
            kyb_pubkey: kyb_pubkey.to_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.address(),
            dlt_root_address: self.root_address(),
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
            dlt_generation: self.dlt_generation,
        };

        kyber_full_kem.kyb_sig_bytes = self.sign(kyber_full_kem.signing_material());
        kyber_full_kem
    }

    fn create_kyber_kem(
        &self,
        mut rng: &mut dyn CryptoRngCore,
        dlt_active_from: Timestamp,
        dlt_expires_at: Timestamp,
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> KyberFullKEM {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);

        let mut pqc_seed = EMPTY_KYBER_SEED;
        rng.fill_bytes(&mut pqc_seed);
        let kyb_privkey = DecapsulationKey::<MlKem768>::from_seed(pqc_seed.into());
        let kyb_pubkey = kyb_privkey.encapsulation_key();

        let mut kyber_full_kem = KyberFullKEM {
            kyb_privkey: kyb_privkey.to_expanded_bytes().into(),
            kyb_pubkey: kyb_pubkey.to_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.address(),
            dlt_root_address: self.root_address(),
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
            dlt_generation: self.dlt_generation,
        };
        kyber_full_kem.kyb_sig_bytes = self.sign(kyber_full_kem.signing_material());
        kyber_full_kem
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
