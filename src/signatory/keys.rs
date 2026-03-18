use super::*;

pub type DilithiumPubkey = [u8; VERIFY_KEY_SZ];
pub type DilithiumPrivkey = [u8; SIGN_KEY_SZ];
pub type XDilithiumPrivkey = [u8; SIGN_KEY_SZ + ENCRYPTED_TAG_SZ];
