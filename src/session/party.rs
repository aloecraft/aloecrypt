use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::kem::*;
use crate::signatory::*;
use crate::traits::*;
use crate::types::*;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Party {
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub session_signature: DilithiumSignature,
    pub delegate_signer: DilithiumSigner,
    pub stable_kem: KyberFullKEM,
    pub session_kem: KyberFullKEM,
    pub stable_secret: AloecryptSecret,
    pub session_secret: AloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct CounterParty {
    pub address: AloecryptAddress,
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
    pub stable_secret: AloecryptSecret,
    pub session_secret: AloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct XParty {
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub session_signature: DilithiumSignature,
    pub x_delegate_signer: XDilithiumSigner,
    pub x_stable_kem: XKyberFullKEM,
    pub x_session_kem: XKyberFullKEM,
    #[serde(with = "BigArray")]
    pub x_stable_secret: XAloecryptSecret,
    #[serde(with = "BigArray")]
    pub x_session_secret: XAloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct XCounterParty {
    pub address: AloecryptAddress,
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
    #[serde(with = "BigArray")]
    pub x_stable_secret: XAloecryptSecret,
    #[serde(with = "BigArray")]
    pub x_session_secret: XAloecryptSecret,
    pub crypt_nonce: [u8; CHACHA_NONCE_SZ],
}
