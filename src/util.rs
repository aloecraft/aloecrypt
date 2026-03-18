use std::ops::Deref;

use super::*;
use crate::consts::*;
use crate::error::*;
use crate::types::*;

pub fn _address(address_seed: &str, addressing_material: Vec<u8>) -> AloecryptAddress {
    let mut aloecrypt_address = EMPTY_ADDRESS;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &address_seed.as_bytes());
    hk.expand(&addressing_material, &mut aloecrypt_address)
        .expect("aloecrypt_address from addressing_material material");
    aloecrypt_address
}

pub fn _hash(hash_seed: &str, hashing_material: Vec<u8>) -> AloecryptHash {
    let mut aloecrypt_hash = EMPTY_HASH;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &hash_seed.as_bytes());
    hk.expand(&hashing_material, &mut aloecrypt_hash)
        .expect("aloecrypt_hash from hashing material");
    aloecrypt_hash
}
