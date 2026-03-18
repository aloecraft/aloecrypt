// src/traits.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::error::*;
use crate::session::builder::*;
use crate::session::message::*;
use crate::session::party::*;
use crate::session::session::*;
use crate::session::*;
use crate::signatory::DilithiumSignature;
use crate::types::*;

// Serializable Traits
// ==================
pub trait AloecryptEmpty {
    fn empty() -> Self;
    fn byte_sz() -> usize;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: Vec<u8>) -> Self;
}

// PEM File Traits
// ==================
pub trait AloecryptPEM {
    fn pem_hdr_tag() -> String;
    fn pem_ftr_tag() -> String;
    fn pem_sz() -> usize;
    fn pem(&self) -> String;
    fn loads(pem: &str) -> Result<Self, AloecryptError>
    where
        Self: Sized;
}

pub trait AloecryptPasswordLockable<X_TYP> {
    fn lock_with_password(
        &self,
        password: &[u8],
        salt: &[u8],
        os_rng: &mut dyn SysRng,
    ) -> Result<X_TYP, AloecryptError>;
    fn unlock_with_password(
        x_obj: X_TYP,
        password: &[u8],
        salt: &[u8],
    ) -> Result<Self, AloecryptError>
    where
        Self: Sized;
}

pub trait AloecryptPasswordPEM<PUB_TYP> {
    fn pem_hdr_tag() -> String;
    fn pem_ftr_tag() -> String;
    fn pem_sz() -> usize;
    fn x_pem(&self, password: &[u8], salt: &[u8], os_rng: &mut impl SysRng) -> String;
    fn x_loads(pem: &str, password: &[u8], salt: &[u8]) -> Result<Self, AloecryptError>
    where
        Self: Sized;

    fn x_pub_loads(pem: &str) -> Result<PUB_TYP, AloecryptError>
    where
        Self: Sized;
}

// Cipher Traits
// ==================
pub trait AloecryptEncapsulator {
    fn encapsulation_key(&self) -> EncapsulationKey<MlKem768>;
}

pub trait AloecryptDecapsulator {
    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768>;
}

// Signatory Traits
// ==================
pub trait AloecryptVerifier {
    fn may_verify(&self) -> bool;
    fn verifying_key(&self) -> VerifyingKey<MlDsa65>;
    fn verify(
        &self,
        signing_material: Vec<u8>,
        sig_bytes: DilithiumSignature,
    ) -> Result<(), AloecryptError> {
        let signature =
            Signature::<MlDsa65>::decode(&sig_bytes.into()).expect("Error decoding signature!");
        self.verifying_key()
            .verify(&(*signing_material), &signature)
            .map_err(|e| AloecryptError::Signature)
    }
}

pub trait AloecryptSigner {
    fn may_sign(&self) -> bool;
    fn signing_key(&self) -> SigningKey<MlDsa65>;
    fn sign(&self, signing_material: Vec<u8>) -> DilithiumSignature {
        self.signing_key()
            .sign(signing_material.as_slice())
            .encode()
            .into()
    }
}

pub trait AloecryptSignable {
    fn signature(&self) -> DilithiumSignature;
    fn signed_by(&self) -> AloecryptAddress;
    fn signing_material(&self) -> Vec<u8>;
}

// Hashing Traits
// ==================
pub trait AloecryptHashable {
    fn hash(&self) -> AloecryptHash;
    fn hashing_material(&self) -> Vec<u8>;
}

pub trait AloecryptXHashable {
    fn hash(&self) -> AloecryptHash;
    fn x_hash(&self) -> AloecryptHash;
    fn x_hashing_material(&self) -> Vec<u8>;
}

pub trait AloecryptHashableKeypair {
    fn pub_hash(&self) -> AloecryptHash;
    fn priv_hash(&self) -> AloecryptHash;
}

pub trait AloecryptHashablePubkey {
    fn pub_hash(&self) -> AloecryptHash;
}

// Addressing Traits
// ==================
pub trait AloecryptAddressable {
    fn generation(&self) -> u64;
    fn address(&self) -> AloecryptAddress;
    fn root_address(&self) -> AloecryptAddress;
    fn addressing_material(&self) -> Vec<u8>;
    fn is_root(&self) -> bool;
}

// Session Traits
// ==================

// Session Builder Traits
// ==================
pub trait AloecryptSessionBuilder {
    fn make_party_intro(&self) -> PartyINTRO;
    fn make_party_challenge(&self) -> Result<PartyCHALLENGE, AloecryptSessionError>;
    fn make_party_challenge_response(&self) -> Result<PartyRESPONSE, AloecryptSessionError>;
    fn make_party_cipher(&self) -> Result<PartyCIPHER, AloecryptSessionError>;
    fn on_counterparty_intro(
        &mut self,
        counterparty_intro: &PartyINTRO,
        os_rng: &mut dyn rand_chacha::rand_core::CryptoRng,
    ) -> Result<(), AloecryptSessionError>;
    fn on_counterparty_cipher(
        &mut self,
        counterparty_cipher: PartyCIPHER,
    ) -> Result<(), AloecryptSessionError>;
    fn on_counterparty_challenge(
        &mut self,
        counterparty_challenge: PartyCHALLENGE,
    ) -> Result<(), AloecryptSessionError>;
    fn on_counterparty_challenge_response(
        &mut self,
        counterparty_challenge_response: PartyRESPONSE,
    ) -> Result<(), AloecryptSessionError>;
    fn build(&self) -> Result<AloecryptSession, AloecryptSessionError>;
}

/*
#[derive(Clone, Deserialize, Serialize)]
pub struct MsgHELLO {
    pub address: AloecryptAddress,  // <-- i.e. "This is the address I intend to use to call you"
    pub intro: PartyINTRO,   // <-- i.e. "This is my info"
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgSYN {
    pub syn_to: [u8; SESSION_NONCE_SZ], // <-- [New] i.e. "Here's your nonce from your intro (these need to match so we both compute the same session salt)"
    pub syn_address: [u8; ADDRESS_SZ], // <-- [New] i.e. "Call me by this"
    pub intro: PartyINTRO, // <-- i.e. "This is my info"
    pub cipher: PartyCIPHER, // <-- i.e. This is the first step in constructing ciphers
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgACK {
    pub ack_to: [u8; SESSION_NONCE_SZ],  // <-- [New] i.e. "Here's your nonce from your intro (these need to match so we both compute the same session salt)"
    pub ack_address: [u8; ADDRESS_SZ],  // <-- [New] i.e. acknowledge: "Ok, I'll call you by this"
    pub cipher: PartyCIPHER, // <-- i.e. Here's my part of the cipher
    pub challenge: PartyCHALLENGE,  // <-- i.e. Here's a challenge constructed from your cipher (with a check so you can confirm that I'm sending properly)
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgSYNACK {
    pub syn_ack: [u8; SESSION_SALT_SZ], // <-- [New] i.e. "Here's that mutually computed salt"
    pub challenge: PartyCHALLENGE, // <-- i.e. Here's a challenge constructed from your cipher (with a check so you can confirm that I'm sending properly)
    pub challenge_response: PartyRESPONSE, // i.e. Here' my answer to your challenge. Is this right?
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgWELCOME {
    pub session_salt: [u8; SESSION_SALT_SZ], // <-- [New] i.e. "Here's that mutually computed salt"
    pub challenge_response: PartyRESPONSE,  // i.e. Here' my answer to your challenge. (you can send a retry or goodbye if there's an issue)
}

pub struct MsgTRANSPORT {  // <-- [New Message] i.e. Let's keep this session but rotate ciphers (Expect ACK)
    pub session_salt: [u8; SESSION_SALT_SZ],
    pub payload: [u8],
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgROTATE { // <-- [New Message] i.e. Let's keep this session but rotate ciphers (Expect ACK)
pub session_salt: [u8; SESSION_SALT_SZ],
pub syn_to: [u8; SESSION_NONCE_SZ],
pub syn_address: [u8; ADDRESS_SZ],
pub cipher: PartyCIPHER, // i.e. This is my new cipher
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgRESYN { // <-- [New Message] i.e. Let's refresh this entire session (Expect SYN)
pub address: AloecryptAddress,
pub intro: PartyINTRO,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgGOODBYE { // <-- [New Message] i.e. For whatever reason I'm disconnecting now
    pub address: AloecryptAddress,
    pub session_salt: [u8; SESSION_SALT_SZ],
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgRETRY { // <-- [New Message] i.e. Retry whatever that last thing was (Probably could be more descriptive)
    pub address: AloecryptAddress,
    pub wait_ms: u64, // <-- wait this long before retrying
    pub detail: [u8;256],
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgERROR { // <-- [New Message] i.e. Some error was encountered
    pub address: AloecryptAddress,
    pub detail: [u8;256],
}


*/
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
