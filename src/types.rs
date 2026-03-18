use super::*;
use crate::consts::*;

pub type DilithiumPubkey = [u8; VERIFY_KEY_SZ];
pub type DilithiumPrivkey = [u8; SIGN_KEY_SZ];
pub type XDilithiumPrivkey = [u8; SIGN_KEY_SZ + ENCRYPTED_TAG_SZ];

pub type KyberPubkey = [u8; ENCAPSULATE_KEY_SZ];
pub type KyberPrivkey = [u8; DECAPSULATE_KEY_SZ];
pub type XKyberPrivkey = [u8; DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ];

pub type AloecryptAddress = [u8; ADDRESS_SZ];
pub type AloecryptHash = [u8; HASH_SZ];
pub type AloecryptSecret = [u8; SECRET_SZ];
pub type XAloecryptSecret = [u8; SECRET_SZ + ENCRYPTED_TAG_SZ];
pub type AloecryptSessionNonce = [u8; SESSION_NONCE_SZ];
pub type AloecryptSessionSalt = [u8; SESSION_SALT_SZ];
pub type XAloecryptSessionSalt = [u8; SESSION_SALT_SZ + ENCRYPTED_TAG_SZ];

pub type Timestamp = [u8; TIMESTAMP_SZ];
