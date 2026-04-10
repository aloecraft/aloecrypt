// src/kem/password.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::password::*;

impl AloecryptPasswordLockable<XKyberFullKEM> for KyberFullKEM {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut rng: &mut dyn CryptoRngCore,
    ) -> Result<XKyberFullKEM, AloecryptError> {
        let mut nonce = EMPTY_CRYPT_NONCE;
        rng.fill_bytes(&mut nonce);
        let x_kyb_privkey_vec =
            password_encrypt(&self.kyb_privkey, &[0u8], password, salt, &nonce)?;
        let x_kyb_privkey: XKyberPrivkey = x_kyb_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        Ok(XKyberFullKEM {
            kyb_pubkey: self.kyb_pubkey,
            x_kyb_privkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_address: self.dlt_root_address,
            dlt_auth_address: self.dlt_auth_address,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            kyb_priv_hash: self.kyb_privkey.hash(),
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            dlt_generation: self.dlt_generation,
            un_hash: self.hash(),
            nonce: nonce,
        })
    }

    fn unlock_with_password(
        x_kem: XKyberFullKEM,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let nonce = &x_kem.nonce;
        let kyb_privkey_vec =
            password_decrypt(&x_kem.x_kyb_privkey, &[0u8], password, salt, nonce)?;
        let kyb_privkey: KyberPrivkey = kyb_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        Ok(Self {
            kyb_pubkey: x_kem.kyb_pubkey,
            kyb_privkey,
            kyb_sig_bytes: x_kem.kyb_sig_bytes,
            dlt_root_pubkey: x_kem.dlt_root_pubkey,
            dlt_auth_pubkey: x_kem.dlt_auth_pubkey,
            dlt_root_address: x_kem.dlt_root_address,
            dlt_auth_address: x_kem.dlt_auth_address,
            dlt_created_at: x_kem.dlt_created_at,
            dlt_active_from: x_kem.dlt_active_from,
            dlt_expires_at: x_kem.dlt_expires_at,
            dlt_refresh_count: x_kem.dlt_refresh_count,
            dlt_max_refresh: x_kem.dlt_max_refresh,
            dlt_generation: x_kem.dlt_generation,
        })
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
