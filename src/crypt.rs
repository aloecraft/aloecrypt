use super::*;
use crate::AloecryptError;
use crate::consts::*;
use std::ops::Deref;

pub struct CryptKey([u8; CHACHA_KEY_SZ]);
#[derive(Clone, Copy)]
pub struct CryptNonce([u8; CHACHA_NONCE_SZ]);

impl CryptNonce {
    pub fn new(rng: &mut impl SysRng) -> Self {
        let mut bytes = [0u8; CHACHA_NONCE_SZ];
        rng.try_fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn load(bytes: &[u8; CHACHA_NONCE_SZ]) -> Self {
        Self(*bytes)
    }

    pub fn as_nonce(&self) -> &Nonce {
        Nonce::from_slice(self.deref())
    }
}

impl std::ops::Deref for CryptNonce {
    type Target = [u8; CHACHA_NONCE_SZ];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for CryptKey {
    type Target = [u8; CHACHA_KEY_SZ];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn password_encrypt(
    bytes: &[u8],
    aad: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: CryptNonce,
) -> Result<Vec<u8>, AloecryptError> {
    let mut chacha_key = EMPTY_CRYPT_KEY;
    pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let payload = Payload {
        msg: bytes,
        aad: aad,
    };
    let encrypted = cipher
        .encrypt(nonce.as_nonce(), payload)
        .map_err(|e| AloecryptError::PasswordEncrypt)?;
    Ok(encrypted)
}

pub fn password_decrypt(
    bytes: &[u8],
    aad: &[u8],
    password: &[u8],
    salt: &[u8],
    nonce: CryptNonce,
) -> Result<Vec<u8>, AloecryptError> {
    let mut chacha_key = EMPTY_CRYPT_KEY;
    pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
    let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
    let payload = Payload {
        msg: bytes,
        aad: aad,
    };
    let encrypted = cipher
        .decrypt(nonce.as_nonce(), payload)
        .map_err(|e| AloecryptError::PasswordDecrypt)?;
    Ok(encrypted)
}
