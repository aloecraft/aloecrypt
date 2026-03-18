use super::*;

impl AloecryptPEM for XDilithiumSigner {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", SIGNER_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", SIGNER_PEM_TAG)
    }
    fn pem_sz() -> usize {
        Self::byte_sz()
            + (Self::byte_sz() / PEM_CHUNK_SZ)
            + XDilithiumSigner::pem_hdr_tag().len()
            + 1
            + XDilithiumSigner::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self.to_bytes();
        let mut out = format!("{}\n", XDilithiumSigner::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", XDilithiumSigner::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&XDilithiumSigner::pem_hdr_tag())
            || !stripped.ends_with(&XDilithiumSigner::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[XDilithiumSigner::pem_hdr_tag().len()
            ..stripped.len() - XDilithiumSigner::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(XDilithiumSigner::from_bytes(bytes))
    }
}

impl AloecryptPEM for DilithiumVerifier {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", VERIFIER_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", VERIFIER_PEM_TAG)
    }
    fn pem_sz() -> usize {
        Self::byte_sz()
            + (Self::byte_sz() / PEM_CHUNK_SZ)
            + DilithiumVerifier::pem_hdr_tag().len()
            + 1
            + DilithiumVerifier::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self.to_bytes();
        let mut out = format!("{}\n", DilithiumVerifier::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", DilithiumVerifier::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&DilithiumVerifier::pem_hdr_tag())
            || !stripped.ends_with(&DilithiumVerifier::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[DilithiumVerifier::pem_hdr_tag().len()
            ..stripped.len() - DilithiumVerifier::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(DilithiumVerifier::from_bytes(bytes))
    }
}

impl AloecryptPEM for DilithiumSignature {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", SIGNATURE_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", SIGNATURE_PEM_TAG)
    }
    fn pem_sz() -> usize {
        SIGNATURE_SZ
            + (SIGNATURE_SZ / PEM_CHUNK_SZ)
            + DilithiumSignature::pem_hdr_tag().len()
            + 1
            + DilithiumSignature::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self;
        let mut out = format!("{}\n", DilithiumSignature::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", DilithiumSignature::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&DilithiumSignature::pem_hdr_tag())
            || !stripped.ends_with(&DilithiumSignature::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[DilithiumSignature::pem_hdr_tag().len()
            ..stripped.len() - DilithiumSignature::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != SIGNATURE_SZ {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(bytes.try_into().unwrap())
    }
}
