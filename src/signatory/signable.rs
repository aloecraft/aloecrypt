use super::*;

impl AloecryptSignable for DilithiumSigner {
    fn signature(&self) -> DilithiumSignature {
        self.dlt_sig_bytes
    }
    fn signed_by(&self) -> AloecryptAddress {
        self.dlt_auth_address
    }
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(HASH_SZ);
        signing_material.extend_from_slice(&self.hash());
        signing_material
    }
}

impl AloecryptSignable for DilithiumVerifier {
    fn signature(&self) -> DilithiumSignature {
        self.dlt_sig_bytes
    }
    fn signed_by(&self) -> AloecryptAddress {
        self.dlt_auth_address
    }
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(HASH_SZ);
        signing_material.extend_from_slice(&self.hash());
        signing_material
    }
}
