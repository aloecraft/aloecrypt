// src/signatory/password_pem.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::crypt::*;

impl AloecryptPasswordPEM<DilithiumVerifier> for DilithiumSigner {
    fn pem_hdr_tag() -> String {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn pem_ftr_tag() -> String {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn pem_sz() -> usize {
        panic!("Should use XDilithiumSigner PEM ")
    }
    fn x_pem(&self, password: &[u8], salt: &[u8], mut os_rng: &mut impl RngCore) -> String {
        let x_self = self
            .lock_with_password(&password, &salt, &mut os_rng)
            .expect("lock_with_password failed during PEM export");
        x_self.pem()
    }

    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let x_dlt = XDilithiumSigner::loads(pem)?;
        let loaded = DilithiumSigner::unlock_with_password(x_dlt, password, salt)?;

        if loaded.dlt_privkey.hash() != x_dlt.dlt_priv_hash {
            return Err(AloecryptError::LoadPEMPrivKeyHash);
        }

        if loaded.hash() != x_dlt.un_hash {
            return Err(AloecryptError::LoadPEMHash);
        }

        Ok(loaded)
    }

    fn x_pub_loads(pem: &str) -> Result<DilithiumVerifier, AloecryptError>
    where
        Self: Sized,
    {
        let x_dlt = XDilithiumSigner::loads(pem)?;
        Ok(x_dlt.read_public())
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
