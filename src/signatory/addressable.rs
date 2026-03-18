use super::*;
use crate::util::_address;

impl AloecryptAddressable for XDilithiumSigner {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_auth_pubkey b/c address is always tied to delegate signer
}

impl AloecryptAddressable for DilithiumSigner {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_auth_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_auth_pubkey b/c address is always tied to delegate signer
}

impl AloecryptAddressable for DilithiumVerifier {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.dlt_generation
    }
    fn address(&self) -> AloecryptAddress {
        _address(ADDRESS_SEED_DLT_SIGNER, self.addressing_material())
    }
    fn root_address(&self) -> AloecryptAddress {
        self.dlt_root_address
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.dlt_auth_pubkey.to_vec()
    }
    // NOTE: ADDRESS_SEED_DLT_SIGNER + dlt_auth_pubkey b/c address is always tied to delegate signer
}
