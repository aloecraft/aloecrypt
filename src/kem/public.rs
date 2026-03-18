use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct KyberPublicKEM {
    #[serde(with = "BigArray")]
    pub kyb_pubkey: KyberPubkey,
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

impl AloecryptEncapsulator for KyberPublicKEM {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        EncapsulationKey::<MlKem768>::new(&(self.kyb_pubkey).into()).unwrap()
    }
}
