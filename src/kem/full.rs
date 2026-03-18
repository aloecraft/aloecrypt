use super::*;
use crate::crypt::*;

// Structs
// ==================
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct KyberFullKEM {
    #[serde(with = "BigArray")]
    pub kyb_pubkey: KyberPubkey,
    #[serde(with = "BigArray")]
    pub kyb_privkey: KyberPrivkey,
    #[serde(with = "BigArray")]
    pub kyb_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
    pub dlt_generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct XKyberFullKEM {
    #[serde(with = "BigArray")]
    pub kyb_pubkey: KyberPubkey,
    #[serde(with = "BigArray")]
    pub x_kyb_privkey: XKyberPrivkey,
    #[serde(with = "BigArray")]
    pub kyb_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub kyb_priv_hash: AloecryptHash,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
    pub dlt_generation: u64,
    pub un_hash: AloecryptHash,
    pub nonce: [u8; CHACHA_NONCE_SZ],
}

impl AloecryptEncapsulator for KyberFullKEM {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        EncapsulationKey::<MlKem768>::new(&(self.kyb_pubkey).into()).unwrap()
    }
}

impl AloecryptDecapsulator for KyberFullKEM {
    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_expanded(&(self.kyb_privkey).into()).unwrap()
    }
}

impl Into<KyberPublicKEM> for KyberFullKEM {
    fn into(self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.dlt_auth_address,
            dlt_root_address: self.dlt_root_address,
            dlt_generation: self.dlt_generation,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
        }
    }
}

impl Into<KyberPublicKEM> for XKyberFullKEM {
    fn into(self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.dlt_auth_address,
            dlt_root_address: self.dlt_root_address,
            dlt_generation: self.dlt_generation,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
        }
    }
}

impl AloecryptPasswordLockable<XKyberFullKEM> for KyberFullKEM {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        mut os_rng: &mut dyn SysRng,
    ) -> Result<XKyberFullKEM, AloecryptError> {
        let nonce = CryptNonce::new(&mut os_rng);
        let x_kyb_privkey_vec = password_encrypt(&self.kyb_privkey, &[0u8], password, salt, nonce)?;
        let x_kyb_privkey: [u8; ENCRYPTED_DECAPSULATE_KEY_SZ] = x_kyb_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordEncrypt)?;
        Ok(XKyberFullKEM {
            kyb_pubkey: self.kyb_pubkey,
            x_kyb_privkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_address: self.dlt_root_address,
            dlt_auth_address: self.dlt_auth_address,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            kyb_priv_hash: self.kyb_privkey.hash(),
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            dlt_generation: self.dlt_generation,
            un_hash: self.hash(),
            nonce: *nonce,
        })
    }

    fn unlock_with_password(
        x_kem: XKyberFullKEM,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError> {
        let nonce = CryptNonce::load(&x_kem.nonce);
        let kyb_privkey_vec =
            password_decrypt(&x_kem.x_kyb_privkey, &[0u8], password, salt, nonce)?;
        let kyb_privkey: [u8; DECAPSULATE_KEY_SZ] = kyb_privkey_vec
            .try_into()
            .map_err(|_| AloecryptError::PasswordDecrypt)?;
        Ok(Self {
            kyb_pubkey: x_kem.kyb_pubkey,
            kyb_privkey,
            kyb_sig_bytes: x_kem.kyb_sig_bytes,
            dlt_root_pubkey: x_kem.dlt_root_pubkey,
            dlt_auth_pubkey: x_kem.dlt_auth_pubkey,
            dlt_root_address: x_kem.dlt_root_address,
            dlt_auth_address: x_kem.dlt_auth_address,
            dlt_created_at: x_kem.dlt_created_at,
            dlt_active_from: x_kem.dlt_active_from,
            dlt_expires_at: x_kem.dlt_expires_at,
            dlt_refresh_count: x_kem.dlt_refresh_count,
            dlt_max_refresh: x_kem.dlt_max_refresh,
            dlt_generation: x_kem.dlt_generation,
        })
    }
}

impl XKyberFullKEM {
    pub fn read_public(&self) -> KyberPublicKEM {
        KyberPublicKEM {
            kyb_pubkey: self.kyb_pubkey,
            kyb_sig_bytes: self.kyb_sig_bytes,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_root_address: self.dlt_root_address,
            dlt_auth_address: self.dlt_auth_address,
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: self.dlt_active_from,
            dlt_expires_at: self.dlt_expires_at,
            dlt_refresh_count: self.dlt_refresh_count,
            dlt_max_refresh: self.dlt_max_refresh,
            dlt_generation: self.dlt_generation,
        }
    }
}
