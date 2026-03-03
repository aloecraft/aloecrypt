// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AloecryptError;
use crate::keypair::Keypair;
use crate::peer_key::PeerKey;
use crate::{MAGIC_BYTES, PrivKey, PubKey};

pub const MAX_FOOTER_BYTES: usize = 65536;
pub const FOOTER_LEN_BYTES: usize = 2;
pub const HDR_SZ_BYTES: usize = 176;

fn ts_bytes_now() -> Vec<u8> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms.to_le_bytes().to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AloecryptFooter {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default = "ts_bytes_now", with = "serde_bytes")]
    pub created_at: Vec<u8>,
}

impl AloecryptFooter {
    pub fn new() -> Self {
        Self {
            description: String::new(),
            metadata: HashMap::new(),
            created_at: ts_bytes_now(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AloecryptError> {
        let msgpack_bytes =
            rmp_serde::to_vec_named(self).map_err(|_| AloecryptError::Serialization)?;

        let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
        encoder
            .write_all(&msgpack_bytes)
            .map_err(|_| AloecryptError::Compression)?;
        let ftr_bytes = encoder.finish().map_err(|_| AloecryptError::Compression)?;

        let ftr_len = ftr_bytes.len();

        if ftr_len > MAX_FOOTER_BYTES - (MAGIC_BYTES.len() + FOOTER_LEN_BYTES) {
            return Err(AloecryptError::Serialization);
        }

        let mut out = Vec::with_capacity(ftr_len + FOOTER_LEN_BYTES + MAGIC_BYTES.len());
        out.extend_from_slice(&ftr_bytes);
        out.extend_from_slice(&(ftr_len as u16).to_le_bytes());
        out.extend_from_slice(&MAGIC_BYTES);

        Ok(out)
    }

    pub fn from_bytes(d: &[u8]) -> Result<Self, AloecryptError> {
        if d.len() < MAGIC_BYTES.len() {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let magic = &d[d.len() - MAGIC_BYTES.len()..];
        if magic != MAGIC_BYTES {
            return Err(AloecryptError::InvalidPemFormat);
        }

        // Get the length of the compressed footer block
        let len_start = d.len() - MAGIC_BYTES.len() - FOOTER_LEN_BYTES;
        let ftr_len_bytes: [u8; 2] = d[len_start..len_start + 2].try_into().unwrap();
        let ftr_len = u16::from_le_bytes(ftr_len_bytes) as usize;

        let block_start = len_start
            .checked_sub(ftr_len)
            .ok_or(AloecryptError::InvalidPemFormat)?;
        let compressed_data = &d[block_start..len_start];

        let mut decoder = lz4_flex::frame::FrameDecoder::new(compressed_data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|_| AloecryptError::Compression)?;

        let footer: AloecryptFooter =
            rmp_serde::from_slice(&decompressed).map_err(|_| AloecryptError::Serialization)?;

        Ok(footer)
    }

    pub fn get_footer_bytes_len(d: &[u8]) -> Result<usize, AloecryptError> {
        if d.len() < MAGIC_BYTES.len() + FOOTER_LEN_BYTES {
            return Err(AloecryptError::InvalidPemFormat);
        }
        let len_start = d.len() - MAGIC_BYTES.len() - FOOTER_LEN_BYTES;
        let ftr_len_bytes: [u8; 2] = d[len_start..len_start + 2].try_into().unwrap();
        let ftr_len = u16::from_le_bytes(ftr_len_bytes) as usize;

        let total = ftr_len + FOOTER_LEN_BYTES + MAGIC_BYTES.len();
        if total > d.len() {
            return Err(AloecryptError::InvalidPemFormat);
        }

        Ok(total)
    }
}

#[derive(Debug, Clone)]
pub struct AloecryptHeader {
    pub peer_addr: [u8; 32],
    pub signer_key: [u8; 32],
    pub app_id_16: [u8; 16],
    pub nonce_16: [u8; 16],
    pub signature: [u8; 64],
}

impl AloecryptHeader {
    pub fn sign(
        d: &[u8],
        app_id_16: &[u8; 16],
        nonce_16: &[u8; 16],
        signer_keypair: &Keypair,
        peer_addr: &[u8; 32],
    ) -> Self {
        let mut payload = Vec::with_capacity(32 + 32 + 16 + 16 + d.len());
        payload.extend_from_slice(peer_addr);
        payload.extend_from_slice(&signer_keypair.public_key);
        payload.extend_from_slice(nonce_16);
        payload.extend_from_slice(app_id_16);
        payload.extend_from_slice(d);

        let signature = signer_keypair.sign(&payload);

        Self {
            peer_addr: *peer_addr,
            signer_key: signer_keypair.public_key,
            app_id_16: *app_id_16,
            nonce_16: *nonce_16,
            signature: signature.to_bytes(),
        }
    }

    pub fn verify(&self, d: &[u8]) -> bool {
        let peer_key = PeerKey {
            cid: [0u8; 16], // Not utilized in raw verification
            public_key: self.signer_key,
        };

        let mut payload = Vec::with_capacity(32 + 32 + 16 + 16 + d.len());
        payload.extend_from_slice(&self.peer_addr);
        payload.extend_from_slice(&self.signer_key);
        payload.extend_from_slice(&self.nonce_16);
        payload.extend_from_slice(&self.app_id_16);
        payload.extend_from_slice(d);

        peer_key.verify(&self.signature, &payload)
    }

    pub fn from_bytes(d: &[u8]) -> Result<Self, AloecryptError> {
        if d.len() < HDR_SZ_BYTES {
            return Err(AloecryptError::InvalidPemFormat);
        }
        if &d[..16] != MAGIC_BYTES {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let mut peer_addr = [0u8; 32];
        peer_addr.copy_from_slice(&d[16..48]);

        let mut signer_key = [0u8; 32];
        signer_key.copy_from_slice(&d[48..80]);

        let mut app_id_16 = [0u8; 16];
        app_id_16.copy_from_slice(&d[80..96]);

        let mut nonce_16 = [0u8; 16];
        nonce_16.copy_from_slice(&d[96..112]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&d[112..176]);

        Ok(Self {
            peer_addr,
            signer_key,
            app_id_16,
            nonce_16,
            signature,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HDR_SZ_BYTES);
        out.extend_from_slice(&MAGIC_BYTES);
        out.extend_from_slice(&self.peer_addr);
        out.extend_from_slice(&self.signer_key);
        out.extend_from_slice(&self.app_id_16);
        out.extend_from_slice(&self.nonce_16);
        out.extend_from_slice(&self.signature);
        out
    }
}

#[derive(Debug, Clone)]
pub struct AloecryptPackage {
    pub hdr: AloecryptHeader,
    pub payload: Vec<u8>,
    pub ftr: AloecryptFooter,
}

impl AloecryptPackage {
    pub fn pack<T: Serialize>(
        o: &T,
        signer_keypair: &Keypair,
        peer_addr: &[u8; 32],
        app_id_16: &[u8; 16],
        nonce_16: &[u8; 16],
    ) -> Result<Self, AloecryptError> {
        let packed = rmp_serde::to_vec_named(o).map_err(|_| AloecryptError::Serialization)?;
        let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
        encoder
            .write_all(&packed)
            .map_err(|_| AloecryptError::Compression)?;
        let compressed = encoder.finish().map_err(|_| AloecryptError::Compression)?;

        let peer_key = PeerKey {
            cid: [0u8; 16], // Not required for DH exchange target
            public_key: *peer_addr,
        };

        let payload = peer_key.send_encrypt(&signer_keypair.x_privkey(), &compressed, nonce_16)?;

        let hdr = AloecryptHeader::sign(&payload, app_id_16, nonce_16, signer_keypair, peer_addr);
        let ftr = AloecryptFooter::new();

        Ok(Self { hdr, payload, ftr })
    }

    pub fn unpack<T: serde::de::DeserializeOwned>(
        &self,
        my_privkey: &Keypair,
    ) -> Result<T, AloecryptError> {
        let peer_key = PeerKey {
            cid: [0u8; 16],
            public_key: self.hdr.signer_key,
        };

        let decrypted =
            peer_key.recv_decrypt(&my_privkey.x_privkey(), &self.payload, &self.hdr.nonce_16)?;

        let mut decoder = lz4_flex::frame::FrameDecoder::new(&decrypted[..]);
        let mut inflated = Vec::new();
        decoder
            .read_to_end(&mut inflated)
            .map_err(|_| AloecryptError::Compression)?;

        let obj = rmp_serde::from_slice(&inflated).map_err(|_| AloecryptError::Serialization)?;

        Ok(obj)
    }

    pub fn from_bytes(d: &[u8]) -> Result<Self, AloecryptError> {
        let wire_ftr_len = AloecryptFooter::get_footer_bytes_len(d)?;

        if d.len() <= HDR_SZ_BYTES + wire_ftr_len {
            return Err(AloecryptError::InvalidPemFormat);
        }

        let hdr = AloecryptHeader::from_bytes(&d[..HDR_SZ_BYTES])?;
        let ftr = AloecryptFooter::from_bytes(&d[d.len() - wire_ftr_len..])?;
        let payload = d[HDR_SZ_BYTES..d.len() - wire_ftr_len].to_vec();

        Ok(Self { hdr, payload, ftr })
    }

    pub fn verify_hdr(&self) -> bool {
        self.hdr.verify(&self.payload)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AloecryptError> {
        let ftr_bytes = self.ftr.to_bytes()?;
        let mut out = Vec::with_capacity(HDR_SZ_BYTES + self.payload.len() + ftr_bytes.len());

        out.extend_from_slice(&self.hdr.to_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&ftr_bytes);

        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_aloecrypt_package_roundtrip() {
        let identity_a = Keypair::new();
        let identity_b = Keypair::new();

        // 1. Build a dummy dictionary object to simulate testing
        let mut test_obj = HashMap::new();
        test_obj.insert("test_key".to_string(), "test_value".to_string());

        let mut nonce_16 = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_16);
        let app_id_16 = b"[_IDENTITY-TEST]";

        // 2. Pack the package
        let package = AloecryptPackage::pack(
            &test_obj,
            &identity_a,
            &identity_b.public_key,
            app_id_16,
            &nonce_16,
        )
        .expect("Packing failed");

        let pkg_bytes = package.to_bytes().unwrap();

        // 3. Reload from raw bytes
        let reloaded_package =
            AloecryptPackage::from_bytes(&pkg_bytes).expect("Failed to reload from bytes");

        // 4. Verification suite
        assert_eq!(&reloaded_package.hdr.app_id_16, app_id_16);
        assert_eq!(reloaded_package.hdr.nonce_16, nonce_16);
        assert_eq!(reloaded_package.hdr.peer_addr, identity_b.public_key);
        assert!(reloaded_package.verify_hdr());

        // 5. Unpack to retrieve original data
        let unpacked_obj: HashMap<String, String> = reloaded_package
            .unpack(&identity_b)
            .expect("Failed to unpack payload");

        assert_eq!(unpacked_obj.get("test_key").unwrap(), "test_value");
    }
    #[test]
    fn test_package_tampering_fails_verification() {
        let identity_a = Keypair::new();
        let identity_b = Keypair::new();

        let test_data = vec![1, 2, 3, 4, 5];
        let mut nonce_16 = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_16);

        let mut package = AloecryptPackage::pack(
            &test_data,
            &identity_a,
            &identity_b.public_key,
            b"[APP_ID_16BYTES]",
            &nonce_16,
        )
        .unwrap();

        // Tamper with the encrypted payload (e.g., a man-in-the-middle bit flip)
        let last_idx = package.payload.len() - 1;
        package.payload[last_idx] ^= 1;

        // 1. The Ed25519 signature verification MUST catch the tampered payload
        assert!(
            !package.verify_hdr(),
            "Tampered payload successfully bypassed signature verification (BAD!)"
        );

        // 2. Even if signature verification was skipped, the ChaCha20Poly1305 MAC MUST fail
        let unpack_result: Result<Vec<i32>, _> = package.unpack(&identity_b);
        assert!(
            matches!(unpack_result, Err(AloecryptError::Cipher(_))),
            "Tampered payload bypassed AEAD authentication (BAD!)"
        );
    }
}
