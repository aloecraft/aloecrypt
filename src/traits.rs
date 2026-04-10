// src/traits.rs
// License: Apache-2.0 (disclaimer at bottom of file)
#![allow(non_camel_case_types)]
use super::*;
use crate::consts::*;
use crate::error::*;
use crate::session::builder::*;
use crate::session::message::*;
use crate::session::session::*;
use crate::session::*;
use crate::types::*;

use ml_kem::{
    B32, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, ExpandedKeyEncoding,
    KeyExport, MlKem768, SharedKey, array::Array,
};
use ml_dsa::signature::{Signer, Verifier, Keypair};
use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};


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
