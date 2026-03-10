use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params, SharedKey, array::Array};
use rand_core::{OsRng, RngCore};
use pbkdf2::pbkdf2_hmac;
use zerocopy::IntoBytes;
use std::fmt::Write;

use super::consts::*;
use super::traits::*;
use crate::error::AloecryptError;

const KYBER_FULL_TAG: &str = "Aloecrypt KyberFullKEM";
const KYBER_PUBLIC_TAG: &str = "Aloecrypt KyberPublicKEM";
const CIPHER_PEM_TAG: &str = "Aloecrypt Cipher";

type KyberCipher = [u8; CIPHER_SZ];

// Structs
// ==================
#[derive(Clone, Copy, Debug)]
pub struct KyberFullKEM {
    pub kyb_pubkey: [u8; ENCAPSULATE_KEY_SZ],
    pub kyb_privkey: [u8; DECAPSULATE_KEY_SZ],
    pub kyb_sig_bytes: [u8; SIGNATURE_SZ],
    pub dlt_address: [u8; ADDRESS_SZ],
    pub dlt_auth_id: [u8; ADDRESS_SZ],

    pub dlt_created_at: [u8; TIMESTAMP_SZ],
    pub dlt_active_from: [u8; TIMESTAMP_SZ],
    pub dlt_expires_at: [u8; TIMESTAMP_SZ],
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct XKyberFullKEM {
    pub kyb_pubkey: [u8; ENCAPSULATE_KEY_SZ],
    pub x_kyb_privkey: [u8; DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ],
    pub kyb_sig_bytes: [u8; SIGNATURE_SZ],
    pub dlt_address: [u8; ADDRESS_SZ],
    pub dlt_auth_id: [u8; ADDRESS_SZ],

    pub dlt_created_at: [u8; TIMESTAMP_SZ],
    pub dlt_active_from: [u8; TIMESTAMP_SZ],
    pub dlt_expires_at: [u8; TIMESTAMP_SZ],
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
    pub nonce: [u8; CHACHA_NONCE_SZ]
}

#[derive(Clone, Copy, Debug)]
pub struct KyberPublicKEM {
    pub kyb_pubkey: [u8; ENCAPSULATE_KEY_SZ],
    pub kyb_sig_bytes: [u8; SIGNATURE_SZ],
    pub dlt_address: [u8; ADDRESS_SZ],
    pub dlt_auth_id: [u8; ADDRESS_SZ],

    pub dlt_created_at: [u8; TIMESTAMP_SZ],
    pub dlt_active_from: [u8; TIMESTAMP_SZ],
    pub dlt_expires_at: [u8; TIMESTAMP_SZ],
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
}

// Trait Implementations (PEM Trait Implementations at bottom of file)
// ==================
impl AloecryptEncapsulator for KyberFullKEM {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768Params> {
        EncapsulationKey::<MlKem768Params>::from_bytes(&(self.kyb_pubkey).into())
    }
}

impl AloecryptEncapsulator for KyberPublicKEM {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768Params> {
        EncapsulationKey::<MlKem768Params>::from_bytes(&(self.kyb_pubkey).into())
    }
}
impl AloecryptDecapsulator for KyberFullKEM {
    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768Params> {
        DecapsulationKey::<MlKem768Params>::from_bytes(&(self.kyb_privkey).into())
    }
}

impl AloecryptSignable for KyberFullKEM {
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(CIPHER_SZ + 32 + 32 + 4*TIMESTAMP_SZ + 8); 
        signing_material.extend_from_slice(&self.kyb_pubkey);
        signing_material.extend_from_slice(&self.dlt_address);
        signing_material.extend_from_slice(&self.dlt_auth_id);
        signing_material.extend_from_slice(&self.dlt_created_at);
        signing_material.extend_from_slice(&self.dlt_active_from);
        signing_material.extend_from_slice(&self.dlt_expires_at);
        signing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        signing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        signing_material
    }
}

impl AloecryptSignable for KyberPublicKEM {
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material = Vec::with_capacity(CIPHER_SZ + 32 + 32 + 4*TIMESTAMP_SZ + 8); 
        signing_material.extend_from_slice(&self.kyb_pubkey);
        signing_material.extend_from_slice(&self.dlt_address);
        signing_material.extend_from_slice(&self.dlt_auth_id);
        signing_material.extend_from_slice(&self.dlt_created_at);
        signing_material.extend_from_slice(&self.dlt_active_from);
        signing_material.extend_from_slice(&self.dlt_expires_at);
        signing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        signing_material.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        signing_material
    }
}

impl Into<KyberPublicKEM> for KyberFullKEM {
    fn into(self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_address: self.dlt_address,
            dlt_auth_id: self.dlt_auth_id,

            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
        }
    }
}

// Implementations
// ==================
impl KyberPublicKEM {
    fn empty(kyb_pubkey: [u8; ENCAPSULATE_KEY_SZ]) -> Self {
        Self {
            kyb_pubkey,
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_address: EMPTY_ADDRESS,
            dlt_auth_id: EMPTY_ADDRESS,
            dlt_created_at: EMPTY_TIMESTAMP,
            dlt_active_from: EMPTY_TIMESTAMP,
            dlt_expires_at: EMPTY_TIMESTAMP,
            dlt_refresh_count: 0,
            dlt_max_refresh: 0,
        }
    }
}

// new KyberFullCipher should only be created by DilithiumSigner.create_cipher
// fn new(mut os_rng: &mut rand_core::OsRng) -> Self {
impl KyberFullKEM { }

// PEM Trait Implementations
// ==================
impl AloecryptPEM for KyberPublicKEM{
    fn byte_sz() -> usize {
        return ENCAPSULATE_KEY_SZ+SIGNATURE_SZ+ADDRESS_SZ+ADDRESS_SZ + TIMESTAMP_SZ + TIMESTAMP_SZ + TIMESTAMP_SZ + 4 + 4;
    }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("-----BEGIN {}v1-----", KYBER_PUBLIC_TAG);
        let ftr_tag: String = format!("-----END {}v1-----", KYBER_PUBLIC_TAG);
        let mut pem_bytes = Vec::with_capacity(Self::byte_sz() + hdr_tag.len() + 1 + ftr_tag.len() + 1 + (Self::byte_sz() / 32));
        pem_bytes.extend_from_slice(&self.kyb_pubkey);
        pem_bytes.extend_from_slice(&self.kyb_sig_bytes);
        pem_bytes.extend_from_slice(&self.dlt_address);
        pem_bytes.extend_from_slice(&self.dlt_auth_id);

        pem_bytes.extend_from_slice(&self.dlt_created_at);
        pem_bytes.extend_from_slice(&self.dlt_active_from);
        pem_bytes.extend_from_slice(&self.dlt_expires_at);
        pem_bytes.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        pem_bytes.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));

        let mut out = format!("{}\n", hdr_tag);
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", ftr_tag).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let hdr_tag: String = format!("-----BEGIN {}v1-----", KYBER_PUBLIC_TAG);
        let ftr_tag: String = format!("-----END {}v1-----", KYBER_PUBLIC_TAG);
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&hdr_tag) || !stripped.ends_with(&ftr_tag) {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[hdr_tag.len()..stripped.len() - ftr_tag.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        let mut byte_offset = 0;
        let mut kyb_pubkey = [0u8; ENCAPSULATE_KEY_SZ];
        kyb_pubkey.copy_from_slice(&bytes[byte_offset..(byte_offset+ENCAPSULATE_KEY_SZ)]);
        byte_offset += ENCAPSULATE_KEY_SZ;
        
        let mut kyb_sig_bytes = [0u8; SIGNATURE_SZ];
        kyb_sig_bytes.copy_from_slice(&bytes[byte_offset..(byte_offset+SIGNATURE_SZ)]);
        byte_offset += SIGNATURE_SZ;
        
        let mut dlt_address = [0u8; ADDRESS_SZ];
        dlt_address.copy_from_slice(&bytes[byte_offset..(byte_offset+ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_auth_id = [0u8; ADDRESS_SZ];
        dlt_auth_id.copy_from_slice(&bytes[byte_offset..(byte_offset+ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_created_at = [0u8; TIMESTAMP_SZ];
        dlt_created_at.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_active_from = [0u8; TIMESTAMP_SZ];
        dlt_active_from.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_expires_at = [0u8; TIMESTAMP_SZ];
        dlt_expires_at.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_refresh_count = [0u8; 4];
        dlt_refresh_count.copy_from_slice(&bytes[(byte_offset)..(byte_offset + 4)]);
        byte_offset += 4;

        let mut dlt_max_refresh = [0u8; 4];
        dlt_max_refresh.copy_from_slice(&bytes[(byte_offset)..(byte_offset + 4)]);

        Ok(Self {
            kyb_pubkey,
            kyb_sig_bytes,
            dlt_address,
            dlt_auth_id,
            dlt_created_at,
            dlt_active_from,
            dlt_expires_at,
            dlt_refresh_count: u32::from_le_bytes(dlt_refresh_count),
            dlt_max_refresh: u32::from_le_bytes(dlt_max_refresh),
        })
    }
}

impl AloecryptPEM for XKyberFullKEM {
    fn byte_sz() -> usize {
        return DECAPSULATE_KEY_SZ+ENCRYPTED_TAG_SZ+ENCAPSULATE_KEY_SZ+SIGNATURE_SZ+ADDRESS_SZ+ADDRESS_SZ+TIMESTAMP_SZ + TIMESTAMP_SZ + TIMESTAMP_SZ + 4 + 4 + CHACHA_NONCE_SZ;
    }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("-----BEGIN {}v1-----", KYBER_FULL_TAG);
        let ftr_tag: String = format!("-----END {}v1-----", KYBER_FULL_TAG);
        let mut pem_bytes = Vec::with_capacity(Self::byte_sz() + hdr_tag.len() + 1 + ftr_tag.len() + 1 + (Self::byte_sz() / 32));
        pem_bytes.extend_from_slice(&self.kyb_pubkey);
        pem_bytes.extend_from_slice(&self.x_kyb_privkey);
        pem_bytes.extend_from_slice(&self.kyb_sig_bytes);
        pem_bytes.extend_from_slice(&self.dlt_address);
        pem_bytes.extend_from_slice(&self.dlt_auth_id);
        pem_bytes.extend_from_slice(&self.dlt_created_at);
        pem_bytes.extend_from_slice(&self.dlt_active_from);
        pem_bytes.extend_from_slice(&self.dlt_expires_at);
        pem_bytes.extend_from_slice(&u32::to_le_bytes(self.dlt_refresh_count));
        pem_bytes.extend_from_slice(&u32::to_le_bytes(self.dlt_max_refresh));
        pem_bytes.extend_from_slice(&self.nonce);
        
        let mut out = format!("{}\n", hdr_tag);
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", ftr_tag).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let hdr_tag: String = format!("-----BEGIN {}v1-----", KYBER_FULL_TAG);
        let ftr_tag: String = format!("-----END {}v1-----", KYBER_FULL_TAG);
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&hdr_tag) || !stripped.ends_with(&ftr_tag) {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[hdr_tag.len()..stripped.len() - ftr_tag.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        let mut byte_offset = 0;
        let mut kyb_pubkey = [0u8; ENCAPSULATE_KEY_SZ];
        kyb_pubkey.copy_from_slice(&bytes[byte_offset..(byte_offset+ENCAPSULATE_KEY_SZ)]);
        byte_offset += ENCAPSULATE_KEY_SZ;

        let mut x_kyb_privkey = [0u8; DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ];
        x_kyb_privkey.copy_from_slice(&bytes[byte_offset..(byte_offset+DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ)]);
        byte_offset += DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ;

        let mut kyb_sig_bytes = [0u8; SIGNATURE_SZ];
        kyb_sig_bytes.copy_from_slice(&bytes[byte_offset..(byte_offset+SIGNATURE_SZ)]);
        byte_offset += SIGNATURE_SZ;

        let mut dlt_address = [0u8; ADDRESS_SZ];
        dlt_address.copy_from_slice(&bytes[byte_offset..(byte_offset+ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_auth_id = [0u8; ADDRESS_SZ];
        dlt_auth_id.copy_from_slice(&bytes[byte_offset..(byte_offset+ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_created_at = [0u8; TIMESTAMP_SZ];
        dlt_created_at.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_active_from = [0u8; TIMESTAMP_SZ];
        dlt_active_from.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_expires_at = [0u8; TIMESTAMP_SZ];
        dlt_expires_at.copy_from_slice(&bytes[(byte_offset)..(byte_offset + TIMESTAMP_SZ)]);
        byte_offset += TIMESTAMP_SZ;

        let mut dlt_refresh_count = [0u8; 4];
        dlt_refresh_count.copy_from_slice(&bytes[(byte_offset)..(byte_offset + 4)]);
        byte_offset += 4;

        let mut dlt_max_refresh = [0u8; 4];
        dlt_max_refresh.copy_from_slice(&bytes[(byte_offset)..(byte_offset + 4)]);
        byte_offset += 4;

        let mut nonce = [0u8; CHACHA_NONCE_SZ];
        nonce.copy_from_slice(&bytes[(byte_offset)..(byte_offset + CHACHA_NONCE_SZ)]);
        

        Ok(Self {
            kyb_pubkey,
            x_kyb_privkey,
            kyb_sig_bytes,
            dlt_address,
            dlt_auth_id,
            dlt_created_at,
            dlt_active_from,
            dlt_expires_at,
            dlt_refresh_count: u32::from_le_bytes(dlt_refresh_count),
            dlt_max_refresh: u32::from_le_bytes(dlt_max_refresh),
            nonce
        })
    }
}

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce};

impl AloecryptPasswordPEM for KyberFullKEM {

    fn x_pem(&self, password: &[u8], salt: &[u8]) -> String{
        let mut os_rng = rand_core::OsRng;
        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);

        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
        let payload = Payload{
            msg: &self.kyb_privkey,
            aad: &[0u8],
        };
        
        let mut nonce_buf = [0u8; CHACHA_NONCE_SZ];
        os_rng.fill_bytes(&mut nonce_buf);
        let nonce = Nonce::from_slice(&nonce_buf);

        let encrypted = cipher.encrypt(nonce, payload).expect("Encryption Error!");

        assert_eq!(encrypted.len(), DECAPSULATE_KEY_SZ+ENCRYPTED_TAG_SZ);

        let x_self = XKyberFullKEM{
            kyb_pubkey : self.kyb_pubkey,
            x_kyb_privkey : encrypted.try_into().expect("Encrypted Length Mismatch"),
            kyb_sig_bytes : self.kyb_sig_bytes,
            dlt_address : self.dlt_address,
            dlt_auth_id : self.dlt_auth_id,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            nonce: nonce_buf
        };
        x_self.pem()
    }

    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError> where Self: Sized {
        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));

        let x_self = XKyberFullKEM::loads(pem).unwrap();
        let payload = Payload {
            msg: &x_self.x_kyb_privkey,
            aad: &[0u8],
        };
        let nonce = Nonce::from_slice(&x_self.nonce);
        let decrypted = cipher.decrypt(nonce, payload)?;
        let mut kyb_privkey = [0u8; DECAPSULATE_KEY_SZ];
        kyb_privkey.copy_from_slice(&decrypted);

        Ok(Self{
            kyb_pubkey : x_self.kyb_pubkey,
            kyb_privkey : kyb_privkey,
            kyb_sig_bytes : x_self.kyb_sig_bytes,
            dlt_address : x_self.dlt_address,
            dlt_auth_id : x_self.dlt_auth_id,
            dlt_created_at: x_self.dlt_created_at,
            dlt_active_from: x_self.dlt_active_from,
            dlt_expires_at: x_self.dlt_expires_at,
            dlt_refresh_count: x_self.dlt_refresh_count,
            dlt_max_refresh: x_self.dlt_max_refresh,
        })
    }
}


impl AloecryptPEM for KyberCipher {
    fn byte_sz() -> usize { CIPHER_SZ }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", CIPHER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", CIPHER_PEM_TAG);
        let mut pem_bytes = Vec::with_capacity(
            Self::byte_sz() + hdr_tag.len() + 1 + ftr_tag.len() + 1 + (Self::byte_sz() / 32),
        );
        pem_bytes.extend_from_slice(self);
        let mut out = format!("{}\n", hdr_tag);
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", ftr_tag).as_str());
        out

    }

    fn loads(pem: &str) -> Result<Self, AloecryptError>{
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", CIPHER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", CIPHER_PEM_TAG);
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&hdr_tag) || !stripped.ends_with(&ftr_tag) {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[hdr_tag.len()..stripped.len() - ftr_tag.len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        let mut byte_offset = 0;
        let mut cipher = [0u8; CIPHER_SZ];
        cipher.copy_from_slice(&bytes[byte_offset..CIPHER_SZ]);
        Ok(cipher)
    }
}