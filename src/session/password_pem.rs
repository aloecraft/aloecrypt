// src/session/password_pem.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptPasswordPEM<CounterParty> for AloecryptSession {
    fn pem_hdr_tag() -> String {
        panic!("Should use XAloecryptSession PEM")
    }
    fn pem_ftr_tag() -> String {
        panic!("Should use XAloecryptSession PEM")
    }
    fn pem_sz() -> usize {
        panic!("Should use XAloecryptSession PEM")
    }

    fn x_pem(&self, password: &[u8], salt: &[u8], mut rng: &mut dyn CryptoRngCore) -> String {
        let x_session = self
            .lock_with_password(password, salt, &mut rng)
            .expect("lock_with_password failed during PEM export");
        x_session.pem()
    }

    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let x_session = XAloecryptSession::loads(pem)?;
        let loaded = AloecryptSession::unlock_with_password(x_session, password, salt)?;

        if loaded.priv_hash() != x_session.priv_hash {
            return Err(AloecryptError::LoadPEMPrivKeyHash);
        }

        if loaded.hash() != x_session.un_hash {
            return Err(AloecryptError::LoadPEMHash);
        }

        Ok(loaded)
    }

    fn x_pub_loads(pem: &str) -> Result<CounterParty, AloecryptError>
    where
        Self: Sized,
    {
        let x_session = XAloecryptSession::loads(pem)?;
        Ok(CounterParty {
            address: x_session.x_counter_party.address,
            nonce: x_session.x_counter_party.nonce,
            signature: x_session.x_counter_party.signature,
            stable_kem: x_session.x_counter_party.stable_kem,
            session_kem: x_session.x_counter_party.session_kem,
            verifier: x_session.x_counter_party.verifier,
            stable_secret: EMPTY_SECRET,
            session_secret: EMPTY_SECRET,
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
