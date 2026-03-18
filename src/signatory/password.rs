// src/signatory/password.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptPasswordLockable<XDilithiumSigner> for DilithiumSigner {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut os_rng: &mut dyn SysRng,
    ) -> Result<XDilithiumSigner, AloecryptError> {
        let nonce = CryptNonce::new(&mut os_rng);
        let x_dlt_privkey_vec = password_encrypt(&self.dlt_privkey, &[0u8], password, salt, nonce)?;
        let x_dlt_privkey: [u8; ENCRYPTED_SIGN_KEY_SZ] = x_dlt_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        Ok(XDilithiumSigner {
            dlt_pubkey: self.dlt_pubkey,
            x_dlt_privkey,
            dlt_sig_bytes: self.dlt_sig_bytes,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_address: self.dlt_root_address,
            dlt_auth_address: self.dlt_auth_address,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_priv_hash: self.dlt_privkey.hash(),
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            dlt_generation: self.dlt_generation,
            un_hash: self.hash(),
            nonce: *nonce,
        })
    }

    fn unlock_with_password(
        x_dlt: XDilithiumSigner,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let nonce = CryptNonce::load(&x_dlt.nonce);
        let dlt_privkey_vec =
            password_decrypt(&x_dlt.x_dlt_privkey, &[0u8], password, salt, nonce)?;
        let dlt_privkey: [u8; SIGN_KEY_SZ] = dlt_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        Ok(Self {
            dlt_pubkey: x_dlt.dlt_pubkey,
            dlt_privkey,
            dlt_root_pubkey: x_dlt.dlt_root_pubkey,
            dlt_auth_pubkey: x_dlt.dlt_auth_pubkey,
            dlt_sig_bytes: x_dlt.dlt_sig_bytes,
            dlt_root_address: x_dlt.dlt_root_address,
            dlt_auth_address: x_dlt.dlt_auth_address,
            dlt_created_at: x_dlt.dlt_created_at,
            dlt_active_from: x_dlt.dlt_active_from,
            dlt_expires_at: x_dlt.dlt_expires_at,
            dlt_refresh_count: x_dlt.dlt_refresh_count,
            dlt_max_refresh: x_dlt.dlt_max_refresh,
            dlt_generation: x_dlt.dlt_generation,
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
