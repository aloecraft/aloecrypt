use super::*;

pub type DilithiumSignature = [u8; SIGNATURE_SZ];

pub struct Authorization {
    address: AloecryptAddress,
    signature: DilithiumSignature,
    auth_by_address: AloecryptAddress,
    auth_by_generation: u64,

    generation: u64,
    from: Timestamp,
    until: Timestamp,
    refresh_remaining: u64,
}

// {"typ":"JWT",
//  "alg":"ML-DSA-65"}

pub struct AuthorizationChainEntry {}
