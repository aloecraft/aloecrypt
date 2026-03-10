use crate::consts::*;
use crate::kem::*;
use crate::traits::*;
use crate::error::AloecryptError;
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{KeyGen, KeyPair, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params, SharedKey, array::Array, B32};
use pbkdf2::pbkdf2_hmac;
use std::fmt::Write;
use crate::time::SystemTime;
use crate::time::UNIX_EPOCH;
use rand_core::RngCore;

const SIGNER_PEM_TAG: &str = "Aloecrypt DilithiumSigner";
const VERIFIER_PEM_TAG: &str = "Aloecrypt DilithiumVerifier";
const SIGNATURE_PEM_TAG: &str = "Aloecrypt DilithiumSignature";

type DilithiumSignature = [u8;SIGNATURE_SZ];

// Structs
// ==================
#[derive(Clone, Copy, Debug)]
pub struct DilithiumSigner {
    pub dlt_pubkey: [u8; VERIFY_KEY_SZ],
    pub dlt_privkey: [u8; SIGN_KEY_SZ],
    pub dlt_sig_bytes: [u8; SIGNATURE_SZ],
    pub dlt_address: [u8; ADDRESS_SZ],
    pub dlt_auth_id: [u8; ADDRESS_SZ],

    pub dlt_created_at: [u8; TIMESTAMP_SZ],
    pub dlt_active_from: [u8; TIMESTAMP_SZ],
    pub dlt_expires_at: [u8; TIMESTAMP_SZ],
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct XDilithiumSigner {
    pub dlt_pubkey: [u8; VERIFY_KEY_SZ],
    pub x_dlt_privkey: [u8; SIGN_KEY_SZ + ENCRYPTED_TAG_SZ],
    pub dlt_sig_bytes: [u8; SIGNATURE_SZ],
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
pub struct DilithiumVerifier {
    pub dlt_pubkey: [u8; VERIFY_KEY_SZ],
    pub dlt_sig_bytes: [u8; SIGNATURE_SZ],
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
impl AloecryptSigner for DilithiumSigner {
    fn signing_key(&self) -> SigningKey<MlDsa65> {
        SigningKey::decode((&self.dlt_privkey).into())
    }
}

impl AloecryptVerifier for DilithiumSigner {
    fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        VerifyingKey::decode((&self.dlt_pubkey).into())
    }
}

impl AloecryptVerifier for DilithiumVerifier {
    fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        VerifyingKey::decode((&self.dlt_pubkey).into())
    }
}

impl From<DilithiumSigner> for DilithiumVerifier {
    fn from(signer: DilithiumSigner) -> DilithiumVerifier {
        DilithiumVerifier {
            dlt_pubkey: signer.dlt_pubkey,
            dlt_sig_bytes: signer.dlt_sig_bytes,
            dlt_address: signer.dlt_address,
            dlt_auth_id: signer.dlt_auth_id,

            dlt_created_at: signer.dlt_created_at,
            dlt_active_from: signer.dlt_active_from,
            dlt_expires_at: signer.dlt_expires_at,
            dlt_refresh_count: signer.dlt_refresh_count,
            dlt_max_refresh: signer.dlt_max_refresh,
        }
    }
}

impl AloecryptSignable for DilithiumSigner {
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material =
            Vec::with_capacity(VERIFY_KEY_SZ + ADDRESS_SZ + 4 * TIMESTAMP_SZ + 8);
        signing_material.extend_from_slice(&self.dlt_pubkey);
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

impl AloecryptSignable for DilithiumVerifier {
    fn signing_material(&self) -> Vec<u8> {
        let mut signing_material =
            Vec::with_capacity(VERIFY_KEY_SZ + ADDRESS_SZ + 4 * TIMESTAMP_SZ + 8);
        signing_material.extend_from_slice(&self.dlt_pubkey);
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

// Implementations
// ==================
impl DilithiumVerifier {
    fn empty(dlt_pubkey: [u8; VERIFY_KEY_SZ]) -> Self {
        Self {
            dlt_pubkey,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_address: EMPTY_ADDRESS,
            dlt_auth_id: EMPTY_ADDRESS,
            dlt_created_at: EMPTY_TIMESTAMP,
            dlt_active_from: EMPTY_TIMESTAMP,
            dlt_expires_at: EMPTY_TIMESTAMP,
            dlt_refresh_count: 0,
            dlt_max_refresh: 0,
        }
    }
    pub fn signing_auth_id(&self) -> [u8; ADDRESS_SZ] {
        _signatory_address(self.dlt_pubkey)
    }

    pub fn is_root_signer(&self) -> bool {
        self.dlt_address == _signatory_address(self.dlt_pubkey)
    }

    pub fn is_time_active(&self) -> bool {
        let now = _ts_bytes_now();
        now > self.dlt_active_from
            && (self.dlt_expires_at == EMPTY_TIMESTAMP || now < self.dlt_expires_at)
    }
}

impl DilithiumSigner {
    pub fn new(mut os_rng: &mut rand_core::OsRng) -> Self {
        let keypair = MlDsa65::key_gen(&mut os_rng);
        let dlt_privkey = keypair.signing_key().encode().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let dlt_address = _signatory_address(dlt_pubkey);
        let dlt_auth_id = _signatory_address(dlt_pubkey);
        let dlt_created_at = _ts_bytes_now();
        let dlt_active_from = EMPTY_TIMESTAMP;
        let dlt_expires_at = EMPTY_TIMESTAMP; // Root signer does not expire
        let dlt_refresh_count = 0;
        let dlt_max_refresh = 0;
        let dlt_signature = _signatory_sign(
            dlt_pubkey,
            dlt_privkey,
            dlt_address,
            dlt_auth_id,
            dlt_created_at,
            dlt_active_from,
            dlt_expires_at,
            dlt_refresh_count,
            dlt_max_refresh,
        );
        Self {
            dlt_privkey: dlt_privkey,
            dlt_pubkey: dlt_pubkey,
            dlt_sig_bytes: dlt_signature,
            dlt_address: dlt_address,
            dlt_auth_id: dlt_auth_id,

            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
        }
    }

    pub fn is_root_signer(&self) -> bool {
        self.dlt_address == _signatory_address(self.dlt_pubkey)
    }

    pub fn is_time_active(&self) -> bool {
        let now = _ts_bytes_now();
        now > self.dlt_active_from
            && (self.dlt_expires_at == EMPTY_TIMESTAMP || now < self.dlt_expires_at)
    }

    pub fn create_dilithium_signer(
        &self,
        mut os_rng: &mut rand_core::OsRng,
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> Self {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);

        let keypair = MlDsa65::key_gen(&mut os_rng);
        let dlt_created_at = _ts_bytes_now();
        let dlt_privkey = keypair.signing_key().encode().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let dlt_auth_id = self.signing_auth_id();
        // NOTE: New signer inherits root address
        let dlt_signature = _signatory_sign(
            dlt_pubkey,
            self.dlt_privkey,
            self.dlt_address,
            dlt_auth_id,
            dlt_created_at,
            dlt_active_from,
            dlt_expires_at,
            dlt_refresh_count,
            dlt_max_refresh,
        );
        Self {
            dlt_privkey: dlt_privkey,
            dlt_pubkey: dlt_pubkey,
            dlt_sig_bytes: dlt_signature,
            dlt_address: self.dlt_address,
            dlt_auth_id: dlt_auth_id,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
        }
    }

    pub fn canonical_kyber_kem(
        &self,
        cannonical_idx: &[u8],
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> KyberFullKEM {


        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);
        let dlt_created_at = _ts_bytes_now();

        let mut kyber_seed = [0u8; 64];
        pbkdf2_hmac::<sha2::Sha256>(
            &self.dlt_privkey,
            &cannonical_idx,
            KEY_ITERS,
            &mut kyber_seed,
        );
        let (kyb_privkey, kyb_pubkey) =
            MlKem768::generate_deterministic(B32::from_slice(&kyber_seed[0..32]), B32::from_slice(&kyber_seed[32..64]));
        let mut cipher = KyberFullKEM {
            kyb_privkey: kyb_privkey.as_bytes().into(),
            kyb_pubkey: kyb_pubkey.as_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_address: self.dlt_address,
            dlt_auth_id: self.signing_auth_id(),
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
        };

        let signing_material = cipher.signing_material();
        cipher.kyb_sig_bytes = self.sign(signing_material);
        cipher
    }

    pub fn create_kyber_kem(
        &self,
        mut os_rng: &mut rand_core::OsRng,
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> KyberFullKEM {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);

        let dlt_created_at = _ts_bytes_now();
        let (kyb_privkey, kyb_pubkey) = MlKem768::generate(&mut os_rng);

        let mut cipher = KyberFullKEM {
            kyb_privkey: kyb_privkey.as_bytes().into(),
            kyb_pubkey: kyb_pubkey.as_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_address: self.dlt_address,
            dlt_auth_id: self.signing_auth_id(),
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
        };

        let signing_material = cipher.signing_material();
        cipher.kyb_sig_bytes = self.sign(signing_material);
        cipher
    }

    pub fn signing_auth_id(&self) -> [u8; ADDRESS_SZ] {
        _signatory_address(self.dlt_pubkey)
    }
}

// Bootstrapping Helpers
// ==================
fn _signatory_sign(
    dlt_pubkey: [u8; VERIFY_KEY_SZ],
    dlt_privkey: [u8; SIGN_KEY_SZ],
    dlt_address: [u8; ADDRESS_SZ],
    dlt_auth_id: [u8; ADDRESS_SZ],
    dlt_created_at: [u8; TIMESTAMP_SZ],
    dlt_active_from: [u8; TIMESTAMP_SZ],
    dlt_expires_at: [u8; TIMESTAMP_SZ],
    dlt_refresh_count: u32,
    dlt_max_refresh: u32,
) -> [u8; SIGNATURE_SZ] {
    let mut signing_material = Vec::with_capacity(VERIFY_KEY_SZ + ADDRESS_SZ);
    signing_material.extend_from_slice(&dlt_pubkey);
    signing_material.extend_from_slice(&dlt_address);
    signing_material.extend_from_slice(&dlt_auth_id);
    signing_material.extend_from_slice(&dlt_created_at);
    signing_material.extend_from_slice(&dlt_active_from);
    signing_material.extend_from_slice(&dlt_expires_at);
    signing_material.extend_from_slice(&u32::to_le_bytes(dlt_refresh_count));
    signing_material.extend_from_slice(&u32::to_le_bytes(dlt_max_refresh));

    SigningKey::<MlDsa65>::decode((&dlt_privkey).into())
        .sign(&(*signing_material))
        .encode()
        .into()
}

fn _signatory_address(dlt_pubkey: [u8; VERIFY_KEY_SZ]) -> [u8; ADDRESS_SZ] {
    let mut addr = [0u8; ADDRESS_SZ];
    pbkdf2_hmac::<sha2::Sha256>(
        dlt_pubkey.as_slice(),
        COM_STRUCT_ID.as_bytes(),
        KEY_ITERS,
        &mut addr,
    );
    addr
}

fn _ts_bytes_now() -> [u8; 8] {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms.to_le_bytes()
}

// PEM Trait Implementations
// ==================
impl AloecryptPEM for DilithiumVerifier {
    fn byte_sz() -> usize {
        return VERIFY_KEY_SZ
            + SIGNATURE_SZ
            + ADDRESS_SZ
            + ADDRESS_SZ
            + TIMESTAMP_SZ
            + TIMESTAMP_SZ
            + TIMESTAMP_SZ
            + 4
            + 4;
    }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", VERIFIER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", VERIFIER_PEM_TAG);
        let mut pem_bytes = Vec::with_capacity(
            Self::byte_sz() + hdr_tag.len() + 1 + ftr_tag.len() + 1 + (Self::byte_sz() / 32),
        );
        pem_bytes.extend_from_slice(&self.dlt_pubkey);
        pem_bytes.extend_from_slice(&self.dlt_sig_bytes);
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
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", VERIFIER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", VERIFIER_PEM_TAG);
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
        let mut dlt_pubkey = [0u8; VERIFY_KEY_SZ];
        dlt_pubkey.copy_from_slice(&bytes[byte_offset..VERIFY_KEY_SZ]);
        byte_offset += VERIFY_KEY_SZ;

        let mut dlt_sig_bytes = [0u8; SIGNATURE_SZ];
        dlt_sig_bytes.copy_from_slice(&bytes[byte_offset..(byte_offset + SIGNATURE_SZ)]);
        byte_offset += SIGNATURE_SZ;

        let mut dlt_address = [0u8; ADDRESS_SZ];
        dlt_address.copy_from_slice(&bytes[byte_offset..(byte_offset + ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_auth_id = [0u8; ADDRESS_SZ];
        dlt_auth_id.copy_from_slice(&bytes[byte_offset..(byte_offset + ADDRESS_SZ)]);
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
            dlt_pubkey,
            dlt_sig_bytes,
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

impl AloecryptPEM for XDilithiumSigner {
    fn byte_sz() -> usize {
        return VERIFY_KEY_SZ
            + SIGN_KEY_SZ
            + ENCRYPTED_TAG_SZ
            + SIGNATURE_SZ
            + ADDRESS_SZ
            + ADDRESS_SZ
            + TIMESTAMP_SZ
            + TIMESTAMP_SZ
            + TIMESTAMP_SZ
            + 4
            + 4
            + CHACHA_NONCE_SZ;
    }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", SIGNER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", SIGNER_PEM_TAG);
        let mut pem_bytes = Vec::with_capacity(
            Self::byte_sz() + hdr_tag.len() + 1 + ftr_tag.len() + 1 + (Self::byte_sz() / 32),
        );
        pem_bytes.extend_from_slice(&self.dlt_pubkey);
        pem_bytes.extend_from_slice(&self.x_dlt_privkey);
        pem_bytes.extend_from_slice(&self.dlt_sig_bytes);
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
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", SIGNER_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", SIGNER_PEM_TAG);
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
        let mut dlt_pubkey = [0u8; VERIFY_KEY_SZ];
        dlt_pubkey.copy_from_slice(&bytes[byte_offset..VERIFY_KEY_SZ]);
        byte_offset += VERIFY_KEY_SZ;

        let mut x_dlt_privkey = [0u8; SIGN_KEY_SZ + ENCRYPTED_TAG_SZ];
        x_dlt_privkey
            .copy_from_slice(&bytes[byte_offset..(byte_offset + SIGN_KEY_SZ + ENCRYPTED_TAG_SZ)]);
        byte_offset += SIGN_KEY_SZ + ENCRYPTED_TAG_SZ;

        let mut dlt_sig_bytes = [0u8; SIGNATURE_SZ];
        dlt_sig_bytes.copy_from_slice(&bytes[byte_offset..(byte_offset + SIGNATURE_SZ)]);
        byte_offset += SIGNATURE_SZ;

        let mut dlt_address = [0u8; ADDRESS_SZ];
        dlt_address.copy_from_slice(&bytes[(byte_offset)..(byte_offset + ADDRESS_SZ)]);
        byte_offset += ADDRESS_SZ;

        let mut dlt_auth_id = [0u8; ADDRESS_SZ];
        dlt_auth_id.copy_from_slice(&bytes[(byte_offset)..(byte_offset + ADDRESS_SZ)]);
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
            dlt_pubkey,
            x_dlt_privkey,
            dlt_sig_bytes,
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

impl AloecryptPasswordPEM for DilithiumSigner {
    fn x_pem(&self, password: &[u8], salt: &[u8]) -> String {
        let mut os_rng = rand_core::OsRng;
        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);

        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));
        let payload = Payload {
            msg: &self.dlt_privkey,
            aad: &[0u8],
        };
        let mut nonce_buf = [0u8; CHACHA_NONCE_SZ];
        os_rng.fill_bytes(&mut nonce_buf);
        let nonce = Nonce::from_slice(&nonce_buf);

        let encrypted = cipher.encrypt(nonce, payload).expect("Encryption Error!");

        assert_eq!(encrypted.len(), SIGN_KEY_SZ + ENCRYPTED_TAG_SZ);

        let x_self = XDilithiumSigner {
            dlt_address: self.dlt_address,
            dlt_pubkey: self.dlt_pubkey,
            x_dlt_privkey: encrypted.try_into().expect("Encrypted Length Mismatch"),
            dlt_sig_bytes: self.dlt_sig_bytes,
            dlt_auth_id: self.dlt_auth_id,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            nonce: nonce_buf
        };
        x_self.pem()
    }

    fn x_loads(
        pem: &str,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError>
    where
        Self: Sized,
    {
        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(password, salt, KEY_ITERS, &mut chacha_key);
        let cipher = ChaCha20Poly1305::new(&ChaChaKey::from(chacha_key));

        let x_self = XDilithiumSigner::loads(pem)?;
        let payload = Payload {
            msg: &x_self.x_dlt_privkey,
            aad: &[0u8],
        };
        let nonce = Nonce::from_slice(&x_self.nonce);
        let decrypted = cipher.decrypt(nonce, payload)?;
        let mut dlt_privkey = [0u8; SIGN_KEY_SZ];
        dlt_privkey.copy_from_slice(&decrypted);

        Ok(Self {
            dlt_address: x_self.dlt_address,
            dlt_pubkey: x_self.dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_sig_bytes: x_self.dlt_sig_bytes,
            dlt_auth_id: x_self.dlt_auth_id,
            dlt_created_at: x_self.dlt_created_at,
            dlt_active_from: x_self.dlt_active_from,
            dlt_expires_at: x_self.dlt_expires_at,
            dlt_refresh_count: x_self.dlt_refresh_count,
            dlt_max_refresh: x_self.dlt_max_refresh,
        })
    }
}

impl AloecryptPEM for DilithiumSignature {
    fn byte_sz() -> usize { SIGNATURE_SZ }
    fn pem(&self) -> String {
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", SIGNATURE_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", SIGNATURE_PEM_TAG);
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
        let hdr_tag: String = format!("----- BEGIN {} v1 -----", SIGNATURE_PEM_TAG);
        let ftr_tag: String = format!("----- END {} v1 -----", SIGNATURE_PEM_TAG);
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
        let mut signature = [0u8; SIGNATURE_SZ];
        signature.copy_from_slice(&bytes[byte_offset..SIGNATURE_SZ]);
        Ok(signature)
    }
}
