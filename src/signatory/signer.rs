use super::signable;
use super::*;
use crate::kem;
use crate::kem::signable::*;

use rand_chacha::rand_core::RngCore;

// Structs
// ==================
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct DilithiumSigner {
    #[serde(with = "BigArray")]
    pub dlt_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_privkey: DilithiumPrivkey,
    #[serde(with = "BigArray")]
    pub dlt_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_generation: u64,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct XDilithiumSigner {
    #[serde(with = "BigArray")]
    pub dlt_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub x_dlt_privkey: XDilithiumPrivkey,
    #[serde(with = "BigArray")]
    pub dlt_sig_bytes: DilithiumSignature,
    #[serde(with = "BigArray")]
    pub dlt_auth_pubkey: DilithiumPubkey,
    #[serde(with = "BigArray")]
    pub dlt_root_pubkey: DilithiumPubkey,
    pub dlt_auth_address: AloecryptAddress,
    pub dlt_root_address: AloecryptAddress,
    pub dlt_created_at: Timestamp,
    pub dlt_active_from: Timestamp,
    pub dlt_expires_at: Timestamp,
    pub dlt_refresh_count: u32,
    pub dlt_max_refresh: u32,
    pub dlt_generation: u64,

    pub dlt_priv_hash: AloecryptHash,
    pub un_hash: AloecryptHash,
    pub nonce: [u8; CHACHA_NONCE_SZ],
}

// Trait Implementations (PEM Trait Implementations at bottom of file)
// ==================
impl AloecryptSigner for DilithiumSigner {
    fn signing_key(&self) -> SigningKey<MlDsa65> {
        SigningKey::from_expanded((&self.dlt_privkey).into())
    }
    fn may_sign(&self) -> bool {
        self.may_verify()
            && (self.dlt_expires_at == EMPTY_TIMESTAMP || _ts_bytes_now() < self.dlt_expires_at)
    }
}

impl AloecryptVerifier for DilithiumSigner {
    fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        VerifyingKey::decode((&self.dlt_pubkey).into())
    }
    fn may_verify(&self) -> bool {
        _ts_bytes_now() > self.dlt_active_from
    }
}

impl DilithiumSigner {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let dlt_created_at = _ts_bytes_now();
        // println!("[DilithiumSigner::new 00  !!!!]");
        // print_stack_remaining();
        let mut dsa_seed = [0u8; 32];
        // println!("[DilithiumSigner::new 01  !!!!]");
        rng.fill_bytes(&mut dsa_seed);
        // println!("[DilithiumSigner::new 02  !!!!]");
        let keypair = MlDsa65::from_seed((&dsa_seed).into());
        // println!("[DilithiumSigner::new 03  !!!!]");
        let dlt_privkey = keypair.signing_key().to_expanded().into();
        // println!("[DilithiumSigner::new 04  !!!!]");
        let dlt_pubkey = keypair.verifying_key().encode().into();
        // println!("[DilithiumSigner::new 05  !!!!]");
        let dlt_active_from = EMPTY_TIMESTAMP;
        let dlt_expires_at = EMPTY_TIMESTAMP; // Root signer does not expire
        let dlt_refresh_count = 0;
        let dlt_max_refresh = 0;
        // println!("[DilithiumSigner::new 06  !!!!]");
        let mut unsigned = Self {
            dlt_pubkey: dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_root_pubkey: dlt_pubkey,
            dlt_auth_pubkey: dlt_pubkey,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_root_address: EMPTY_ADDRESS,
            dlt_auth_address: EMPTY_ADDRESS,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: 0u32,
            dlt_max_refresh: 0u32,
            dlt_generation: 0u64,
        };
        // println!("[DilithiumSigner::new 07  !!!!]");
        unsigned.dlt_root_address = unsigned.address();
        // println!("[DilithiumSigner::new 08  !!!!]");
        unsigned.dlt_auth_address = unsigned.address();
        // println!("[DilithiumSigner::new 09  !!!!]");
        unsigned.dlt_sig_bytes = unsigned.sign(unsigned.signing_material());
        // println!("[DilithiumSigner::new 10  !!!!]");
        unsigned
    }

    pub fn create_dilithium_signer(
        &self,
        rng: &mut impl RngCore,
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> Self {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);

        let dlt_created_at = _ts_bytes_now();

        let mut dsa_seed = [0u8; 32];
        rng.fill_bytes(&mut dsa_seed);
        let keypair = MlDsa65::from_seed((&dsa_seed).into());
        let dlt_privkey = keypair.signing_key().to_expanded().into();
        let dlt_pubkey = keypair.verifying_key().encode().into();
        let mut unsigned = Self {
            dlt_pubkey: dlt_pubkey,
            dlt_privkey: dlt_privkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_sig_bytes: EMPTY_SIGNATURE,
            dlt_root_address: EMPTY_ADDRESS,
            dlt_auth_address: EMPTY_ADDRESS,
            dlt_created_at: dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: 0u32,
            dlt_max_refresh: 0u32,
            dlt_generation: self.generation() + 1,
        };

        unsigned.dlt_root_address = self.root_address();
        unsigned.dlt_auth_address = self.address();
        unsigned.dlt_sig_bytes = self.sign(unsigned.signing_material());
        unsigned
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
        let kyb_privkey = DecapsulationKey::<MlKem768>::from_seed(kyber_seed.into());
        let kyb_pubkey = kyb_privkey.encapsulation_key();

        let mut kyber_full_kem = KyberFullKEM {
            kyb_privkey: kyb_privkey.to_expanded_bytes().into(),
            kyb_pubkey: kyb_pubkey.to_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.address(),
            dlt_root_address: self.root_address(),
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
            dlt_generation: self.dlt_generation,
        };

        kyber_full_kem.kyb_sig_bytes = self.sign(kyber_full_kem.signing_material());
        kyber_full_kem
    }

    pub fn create_kyber_kem(
        &self,
        mut os_rng: &mut impl SysRng,
        dlt_active_from: [u8; TIMESTAMP_SZ],
        dlt_expires_at: [u8; TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh: u32,
    ) -> KyberFullKEM {
        assert!(dlt_expires_at <= self.dlt_expires_at || self.dlt_expires_at == EMPTY_TIMESTAMP);
        assert!(dlt_active_from >= self.dlt_active_from);

        let mut pqc_seed = [0u8; PQC_SEED_SZ];
        os_rng.try_fill_bytes(&mut pqc_seed);
        let kyb_privkey = DecapsulationKey::<MlKem768>::from_seed(pqc_seed.into());
        let kyb_pubkey = kyb_privkey.encapsulation_key();

        let mut kyber_full_kem = KyberFullKEM {
            kyb_privkey: kyb_privkey.to_expanded_bytes().into(),
            kyb_pubkey: kyb_pubkey.to_bytes().into(),
            kyb_sig_bytes: EMPTY_SIGNATURE,
            dlt_auth_pubkey: self.dlt_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_address: self.address(),
            dlt_root_address: self.root_address(),
            dlt_created_at: self.dlt_created_at,
            dlt_active_from: dlt_active_from,
            dlt_expires_at: dlt_expires_at,
            dlt_refresh_count: dlt_refresh_count,
            dlt_max_refresh: dlt_max_refresh,
            dlt_generation: self.dlt_generation,
        };

        kyber_full_kem.kyb_sig_bytes = self.sign(kyber_full_kem.signing_material());
        kyber_full_kem
    }
}

impl XDilithiumSigner {
    pub fn read_public(&self) -> DilithiumVerifier {
        DilithiumVerifier {
            dlt_pubkey: self.dlt_pubkey,
            dlt_root_pubkey: self.dlt_root_pubkey,
            dlt_auth_pubkey: self.dlt_auth_pubkey,
            dlt_sig_bytes: self.dlt_sig_bytes,
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
