use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::error::AloecryptError;
use crate::kem::*;
use crate::option_big_array;
use crate::time::{SystemTime, UNIX_EPOCH};
use crate::traits::*;
use crate::types::*;
use crate::util::*;

pub mod addressable;
pub mod empty;
pub mod hashable;
pub mod jwt;
pub mod keys;
pub mod password;
pub mod password_pem;
pub mod pem;
pub mod signable;
pub mod signature;
pub mod signer;
pub mod verifier;

pub use empty::*;
pub use hashable::*;
pub use pem::*;
pub use signable::*;
pub use signature::*;
pub use signer::*;
pub use verifier::*;
// pub use keys::*;
pub use addressable::*;
pub use jwt::*;
pub use password::*;
pub use password_pem::*;

const SIGNER_PEM_TAG: &str = "Aloecrypt DilithiumSigner";
const VERIFIER_PEM_TAG: &str = "Aloecrypt DilithiumVerifier";
const SIGNATURE_PEM_TAG: &str = "Aloecrypt DilithiumSignature";

fn _ts_bytes_now() -> [u8; 8] {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms.to_le_bytes()
}

// fn _signatory_address(dlt_pubkey: [u8; VERIFY_KEY_SZ]) -> [u8; ADDRESS_SZ] {
//     let mut addr = [0u8; ADDRESS_SZ];
//     pbkdf2_hmac::<sha2::Sha256>(
//         dlt_pubkey.as_slice(),
//         COM_STRUCT_ID.as_bytes(),
//         KEY_ITERS,
//         &mut addr,
//     );
//     addr
// }
// fn _address(address_seed: &str, addressing_material:vec<u8>) -> AloecryptAddress {
//     let mut aloecrypt_address = EMPTY_ADDRESS;
//     let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &address_seed.as_bytes());
//     hk.expand(&addressing_material, &mut aloecrypt_address)
//         .expect("aloecrypt_address from addressing_material material");
//     aloecrypt_address
// }
// fn _hash(hash_seed: &str, hashing_material:vec<u8>) -> AloecryptHash {
//     let mut aloecrypt_hash = EMPTY_HASH;
//     let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &hash_seed.as_bytes());
//     hk.expand(&hashing_material, &mut aloecrypt_hash)
//         .expect("aloecrypt_hash from hashing material");
//     aloecrypt_hash
// }
