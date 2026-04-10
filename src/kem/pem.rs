// src/kem/pem.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptPEM for XKyberFullKEM {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", KYBER_FULL_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", KYBER_FULL_PEM_TAG)
    }
    fn pem_sz() -> usize {
        Self::byte_sz()
            + (Self::byte_sz() / PEM_CHUNK_SZ)
            + XKyberFullKEM::pem_hdr_tag().len()
            + 1
            + XKyberFullKEM::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self.to_bytes();
        let mut out = format!("{}\n", XKyberFullKEM::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", XKyberFullKEM::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&XKyberFullKEM::pem_hdr_tag())
            || !stripped.ends_with(&XKyberFullKEM::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[XKyberFullKEM::pem_hdr_tag().len()
            ..stripped.len() - XKyberFullKEM::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(XKyberFullKEM::from_bytes(bytes))
    }
}

impl AloecryptPEM for KyberPublicKEM {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", KYBER_PUBLIC_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", KYBER_PUBLIC_PEM_TAG)
    }
    fn pem_sz() -> usize {
        Self::byte_sz()
            + (Self::byte_sz() / PEM_CHUNK_SZ)
            + KyberPublicKEM::pem_hdr_tag().len()
            + 1
            + KyberPublicKEM::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self.to_bytes();
        let mut out = format!("{}\n", KyberPublicKEM::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", KyberPublicKEM::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&KyberPublicKEM::pem_hdr_tag())
            || !stripped.ends_with(&KyberPublicKEM::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[KyberPublicKEM::pem_hdr_tag().len()
            ..stripped.len() - KyberPublicKEM::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(KyberPublicKEM::from_bytes(bytes))
    }
}

impl AloecryptPEM for KyberCipher {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", CIPHER_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", CIPHER_PEM_TAG)
    }
    fn pem_sz() -> usize {
        CIPHER_SZ
            + (CIPHER_SZ / PEM_CHUNK_SZ)
            + KyberCipher::pem_hdr_tag().len()
            + 1
            + KyberCipher::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self;
        let mut out = format!("{}\n", KyberCipher::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", KyberCipher::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&KyberCipher::pem_hdr_tag())
            || !stripped.ends_with(&KyberCipher::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped
            [KyberCipher::pem_hdr_tag().len()..stripped.len() - KyberCipher::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;

        if bytes.len() != CIPHER_SZ {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(bytes.try_into().unwrap())
    }
}
// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
