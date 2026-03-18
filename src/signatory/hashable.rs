use super::*;

impl AloecryptHashable for DilithiumPubkey {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_DLT_PUBKEY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl AloecryptHashable for DilithiumPrivkey {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_DLT_PRIVKEY, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl AloecryptXHashable for XDilithiumSigner {
    fn hash(&self) -> AloecryptHash {
        self.un_hash
    }
    fn x_hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_DLT_X_SIGNER, self.x_hashing_material())
    }
    fn x_hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(HASH_SZ + HASH_SZ + CHACHA_NONCE_SZ);
        hashing_material.extend_from_slice(&self.dlt_priv_hash);
        hashing_material.extend_from_slice(&self.un_hash);
        hashing_material.extend_from_slice(&self.nonce);
        hashing_material
    }
}

impl AloecryptHashable for DilithiumVerifier {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_DLT_SIGNER, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            HASH_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + 16,
        );
        hashing_material.extend_from_slice(&self.pub_hash());
        hashing_material.extend_from_slice(&self.address());
        hashing_material.extend_from_slice(&self.dlt_auth_address);
        hashing_material.extend_from_slice(&self.dlt_root_address);
        hashing_material.extend_from_slice(&self.dlt_created_at);
        hashing_material.extend_from_slice(&self.dlt_active_from);
        hashing_material.extend_from_slice(&self.dlt_expires_at);
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        hashing_material.extend_from_slice(&u64::to_le_bytes(self.generation()));
        hashing_material
    }
}

impl AloecryptHashable for DilithiumSigner {
    fn hash(&self) -> AloecryptHash {
        _hash(HASH_SEED_DLT_SIGNER, self.hashing_material())
    }
    fn hashing_material(&self) -> Vec<u8> {
        let mut hashing_material = Vec::with_capacity(
            HASH_SZ
                + HASH_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + ADDRESS_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + TIMESTAMP_SZ
                + 16,
        );
        hashing_material.extend_from_slice(&self.pub_hash());
        hashing_material.extend_from_slice(&self.address());
        hashing_material.extend_from_slice(&self.dlt_auth_address);
        hashing_material.extend_from_slice(&self.dlt_root_address);
        hashing_material.extend_from_slice(&self.dlt_created_at);
        hashing_material.extend_from_slice(&self.dlt_active_from);
        hashing_material.extend_from_slice(&self.dlt_expires_at);
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        hashing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        hashing_material.extend_from_slice(&u64::to_le_bytes(self.generation()));
        hashing_material
    }
}

impl AloecryptHashableKeypair for DilithiumSigner {
    fn pub_hash(&self) -> AloecryptHash {
        self.dlt_pubkey.hash()
    }
    fn priv_hash(&self) -> AloecryptHash {
        self.dlt_privkey.hash()
    }
}

impl AloecryptHashableKeypair for XDilithiumSigner {
    fn pub_hash(&self) -> AloecryptHash {
        self.dlt_pubkey.hash()
    }
    fn priv_hash(&self) -> AloecryptHash {
        self.dlt_priv_hash
    }
}

impl AloecryptHashablePubkey for DilithiumVerifier {
    fn pub_hash(&self) -> AloecryptHash {
        self.dlt_pubkey.hash()
    }
}
