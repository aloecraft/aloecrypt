// src/session/password.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptPasswordLockable<XAloecryptSession> for AloecryptSession {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut rng: &mut dyn CryptoRngCore,
    ) -> Result<XAloecryptSession, AloecryptError> {
        let x_party = self.party.lock_with_password(password, salt, &mut rng)?;
        let x_counter_party = self
            .counter_party
            .lock_with_password(password, salt, &mut rng)?;
        let x_session_salt_vec = password_encrypt(
            &self.session_salt,
            &[0u8],
            password,
            salt,
            &x_counter_party.crypt_nonce,
        )?;
        let x_session_salt: XAloecryptSessionSalt = x_session_salt_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        Ok(XAloecryptSession {
            x_party,
            x_counter_party,
            x_session_salt,
            un_hash: self.hash(),
            priv_hash: self.priv_hash(),
        })
    }

    fn unlock_with_password(
        x_obj: XAloecryptSession,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let party = Party::unlock_with_password(x_obj.x_party, password, salt)?;
        let counter_party =
            CounterParty::unlock_with_password(x_obj.x_counter_party, password, salt)?;
        let session_salt_vec = password_decrypt(
            &x_obj.x_session_salt,
            &[0u8],
            password,
            salt,
            &x_obj.x_counter_party.crypt_nonce,
        )?;
        let session_salt = session_salt_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        Ok(Self {
            party,
            counter_party,
            session_salt,
        })
    }
}

impl AloecryptPasswordLockable<XParty> for Party {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut rng: &mut dyn CryptoRngCore,
    ) -> Result<XParty, AloecryptError> {
        let x_delegate_signer = self
            .delegate_signer
            .lock_with_password(password, salt, &mut rng)?;
        let x_stable_kem = self
            .stable_kem
            .lock_with_password(password, salt, &mut rng)?;
        let x_session_kem = self
            .session_kem
            .lock_with_password(password, salt, &mut rng)?;

        let x_stable_secret_vec = password_encrypt(
            &self.stable_secret,
            &[0u8],
            password,
            salt,
            &x_session_kem.nonce,
        )?;
        let x_session_secret_vec = password_encrypt(
            &self.session_secret,
            &[0u8],
            password,
            salt,
            &x_session_kem.nonce,
        )?;

        let x_stable_secret: XAloecryptSecret = x_stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        let x_session_secret: XAloecryptSecret = x_session_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;

        Ok(XParty {
            nonce: self.nonce,
            session_signature: self.session_signature,
            x_delegate_signer,
            x_stable_kem,
            x_session_kem,
            x_stable_secret,
            x_session_secret,
        })
    }

    fn unlock_with_password(
        x_obj: XParty,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let delegate_signer =
            DilithiumSigner::unlock_with_password(x_obj.x_delegate_signer, password, salt)?;
        let stable_kem = KyberFullKEM::unlock_with_password(x_obj.x_stable_kem, password, salt)?;
        let session_kem = KyberFullKEM::unlock_with_password(x_obj.x_session_kem, password, salt)?;

        let stable_secret_vec = password_decrypt(
            &x_obj.x_stable_secret,
            &[0u8],
            password,
            salt,
            &x_obj.x_session_kem.nonce,
        )?;
        let session_secret_vec = password_decrypt(
            &x_obj.x_session_secret,
            &[0u8],
            password,
            salt,
            &x_obj.x_session_kem.nonce,
        )?;

        let stable_secret: AloecryptSecret = stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        let session_secret: AloecryptSecret = session_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;

        Ok(Self {
            nonce: x_obj.nonce,
            session_signature: x_obj.session_signature,
            delegate_signer,
            stable_kem,
            session_kem,
            stable_secret,
            session_secret,
        })
    }
}

impl AloecryptPasswordLockable<XCounterParty> for CounterParty {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<XCounterParty, AloecryptError> {
        let mut crypt_nonce = EMPTY_CRYPT_NONCE;
        rng.fill_bytes(&mut crypt_nonce);

        let x_stable_secret_vec =
            password_encrypt(&self.stable_secret, &[0u8], password, salt, &crypt_nonce)?;
        let x_session_secret_vec =
            password_encrypt(&self.session_secret, &[0u8], password, salt, &crypt_nonce)?;

        let x_stable_secret: XAloecryptSecret = x_stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        let x_session_secret: XAloecryptSecret = x_session_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;

        Ok(XCounterParty {
            nonce: self.nonce,
            address: self.address,
            signature: self.signature,
            verifier: self.verifier,
            stable_kem: self.stable_kem,
            session_kem: self.session_kem,
            x_stable_secret,
            x_session_secret,
            crypt_nonce,
        })
    }

    fn unlock_with_password(
        x_obj: XCounterParty,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let stable_secret_vec = password_decrypt(
            &x_obj.x_stable_secret,
            &[0u8],
            password,
            salt,
            &x_obj.crypt_nonce,
        )?;
        let session_secret_vec = password_decrypt(
            &x_obj.x_session_secret,
            &[0u8],
            password,
            salt,
            &x_obj.crypt_nonce,
        )?;

        let stable_secret: AloecryptSecret = stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        let session_secret: AloecryptSecret = session_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;

        Ok(Self {
            nonce: x_obj.nonce,
            address: x_obj.address,
            signature: x_obj.signature,
            verifier: x_obj.verifier,
            stable_kem: x_obj.stable_kem,
            session_kem: x_obj.session_kem,
            stable_secret,
            session_secret,
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
