use super::party::*;
use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::kem::*;
use crate::signatory::*;
use crate::traits::*;
use crate::types::*;

use rand_core::RngCore;

impl AloecryptPasswordLockable<XParty> for Party {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut os_rng: &mut dyn SysRng,
    ) -> Result<XParty, AloecryptError> {
        let x_delegate_signer =
            self.delegate_signer
                .lock_with_password(password, salt, &mut os_rng)?;
        let x_stable_kem = self
            .stable_kem
            .lock_with_password(password, salt, &mut os_rng)?;
        let x_session_kem = self
            .session_kem
            .lock_with_password(password, salt, &mut os_rng)?;

        let x_stable_secret_vec = password_encrypt(
            &self.stable_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_session_kem.nonce),
        )?;
        let x_session_secret_vec = password_encrypt(
            &self.session_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_session_kem.nonce),
        )?;

        let x_stable_secret: [u8; SECRET_SZ + ENCRYPTED_TAG_SZ] = x_stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        let x_session_secret: [u8; SECRET_SZ + ENCRYPTED_TAG_SZ] = x_session_secret_vec
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
            CryptNonce::load(&x_obj.x_session_kem.nonce),
        )?;
        let session_secret_vec = password_decrypt(
            &x_obj.x_session_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_obj.x_session_kem.nonce),
        )?;

        let stable_secret: [u8; SECRET_SZ] = stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        let session_secret: [u8; SECRET_SZ] = session_secret_vec
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
        mut os_rng: &mut dyn SysRng,
    ) -> Result<XCounterParty, AloecryptError> {
        let mut crypt_nonce = [0u8; CHACHA_NONCE_SZ];
        os_rng.try_fill_bytes(&mut crypt_nonce);

        let x_stable_secret_vec = password_encrypt(
            &self.stable_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&crypt_nonce),
        )?;
        let x_session_secret_vec = password_encrypt(
            &self.session_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&crypt_nonce),
        )?;

        let x_stable_secret: [u8; SECRET_SZ + ENCRYPTED_TAG_SZ] = x_stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        let x_session_secret: [u8; SECRET_SZ + ENCRYPTED_TAG_SZ] = x_session_secret_vec
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
            CryptNonce::load(&x_obj.crypt_nonce),
        )?;
        let session_secret_vec = password_decrypt(
            &x_obj.x_session_secret,
            &[0u8],
            password,
            salt,
            CryptNonce::load(&x_obj.crypt_nonce),
        )?;

        let stable_secret: [u8; SECRET_SZ] = stable_secret_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        let session_secret: [u8; SECRET_SZ] = session_secret_vec
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
