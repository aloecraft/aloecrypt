// src/session/message.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::error::*;
use crate::kem::{KyberFullKEM, KyberPublicKEM};
use crate::session::builder::{
    CounterPartyCHALLENGE, CounterPartySECRET, FullCIPHER, PartyCHALLENGE, PartyCIPHER, PartyINTRO,
    PartyRESPONSE,
};
use crate::session::util::{cipher_pair, cipher_salt, nonce_pair};
use crate::signatory::{DilithiumSigner, DilithiumVerifier};
use crate::types::*;

use crate::option_big_array;

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgHELLO {
    pub address: AloecryptAddress,
    pub intro: PartyINTRO,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgSYN {
    pub syn_to: [u8; SESSION_NONCE_SZ],
    pub syn_address: [u8; ADDRESS_SZ],
    pub intro: PartyINTRO,
    pub cipher: PartyCIPHER,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgACK {
    pub ack_to: [u8; SESSION_NONCE_SZ],
    pub ack_address: [u8; ADDRESS_SZ],
    pub cipher: PartyCIPHER,
    pub challenge: PartyCHALLENGE,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgSYNACK {
    pub syn_ack: [u8; SESSION_SALT_SZ],
    pub challenge: PartyCHALLENGE,
    pub challenge_response: PartyRESPONSE,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgWELCOME {
    pub challenge_response: PartyRESPONSE,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgGOODBYE {
    pub address: AloecryptAddress,
    pub session_salt: [u8; SESSION_SALT_SZ],
}

pub struct MsgTRANSPORT {
    // <-- [New Message] i.e. Let's keep this session but rotate ciphers (Expect ACK)
    pub session_salt: [u8; SESSION_SALT_SZ],
    pub payload: [u8],
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgRETRY {
    pub address: AloecryptAddress,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgROTATE {
    pub session_salt: [u8; SESSION_SALT_SZ],
    pub syn_to: [u8; SESSION_NONCE_SZ],
    pub syn_address: [u8; ADDRESS_SZ],
    pub cipher: PartyCIPHER,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgRESYN {
    pub address: AloecryptAddress,
    pub intro: PartyINTRO,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MsgERROR {
    // <-- [New Message] i.e. Some error was encountered
    pub address: AloecryptAddress,
}

pub fn send_encrypt(
    payload: &[u8],
    sender: FullCIPHER,
    receiver: CounterPartySECRET,
    session_salt: &[u8; SESSION_SALT_SZ],
    receiver_nonce: &[u8; SESSION_NONCE_SZ],
    receiver_address: &[u8; ADDRESS_SZ],
    sender_nonce: &[u8; SESSION_NONCE_SZ],
    sender_address: &[u8; ADDRESS_SZ],
) -> Result<Vec<u8>, AloecryptSessionError> {
    let (session_nonce_bytes, stable_nonce_bytes) =
        nonce_pair(&session_salt, NONCE_MSG_SESSION_SEED, NONCE_MSG_STABLE_SEED);

    let receiver_salt = cipher_salt(
        NONCE_MSG_SESSION_SEED.as_bytes(),
        session_salt,
        sender_nonce,
        receiver_nonce,
        receiver_address,
    );

    let sender_salt = cipher_salt(
        NONCE_MSG_SESSION_SEED.as_bytes(),
        session_salt,
        receiver_nonce,
        sender_nonce,
        sender_address,
    );

    // println!("Send Encrypt:");
    // println!("receiver_address: {:x?}", receiver_address);
    // println!("receiver_nonce: {:x?}", receiver_nonce);
    // println!("receiver_salt: {:x?}", receiver_salt);
    // println!("sender_address: {:x?}", sender_address);
    // println!("sender_nonce: {:x?}", sender_nonce);
    // println!("sender_salt: {:x?}", sender_salt);

    let (session_cipher, stable_cipher) = cipher_pair(
        &sender_salt,
        &sender.session_secret,
        &receiver_salt,
        &receiver.stable_secret,
    );

    let session_crypt_payload = session_cipher
        .encrypt(
            Nonce::from_slice(&session_nonce_bytes),
            Payload {
                msg: &payload,
                aad: &sender.signature,
            },
        )
        .map_err(|e| AloecryptSessionError::SendEncryptError(e))?;

    let stable_crypt_payload = stable_cipher
        .encrypt(
            Nonce::from_slice(&stable_nonce_bytes),
            Payload {
                msg: &session_crypt_payload,
                aad: &receiver.signature,
            },
        )
        .map_err(|e| AloecryptSessionError::SendEncryptError(e))?;

    Ok(stable_crypt_payload)
}

pub fn recv_decrypt(
    payload: &[u8],
    sender: CounterPartySECRET,
    receiver: FullCIPHER,
    session_salt: &[u8; SESSION_SALT_SZ],
    receiver_nonce: &[u8; SESSION_NONCE_SZ],
    receiver_address: &[u8; ADDRESS_SZ],
    sender_nonce: &[u8; SESSION_NONCE_SZ],
    sender_address: &[u8; ADDRESS_SZ],
) -> Result<Vec<u8>, AloecryptSessionError> {
    let (session_nonce_bytes, stable_nonce_bytes) =
        nonce_pair(&session_salt, NONCE_MSG_SESSION_SEED, NONCE_MSG_STABLE_SEED);

    let receiver_salt = cipher_salt(
        NONCE_MSG_SESSION_SEED.as_bytes(),
        session_salt,
        sender_nonce,
        receiver_nonce,
        receiver_address,
    );

    let sender_salt = cipher_salt(
        NONCE_MSG_SESSION_SEED.as_bytes(),
        session_salt,
        receiver_nonce,
        sender_nonce,
        sender_address,
    );

    // println!("Recv Decrypt:");
    // println!("receiver_address: {:x?}", receiver_address);
    // println!("receiver_nonce: {:x?}", receiver_nonce);
    // println!("receiver_salt: {:x?}", receiver_salt);
    // println!("sender_address: {:x?}", sender_address);
    // println!("sender_nonce: {:x?}", sender_nonce);
    // println!("sender_salt: {:x?}", sender_salt);

    let (session_cipher, stable_cipher) = cipher_pair(
        &sender_salt,
        &sender.session_secret,
        &receiver_salt,
        &receiver.stable_secret,
    );

    let stable_decrypt_payload = stable_cipher
        .decrypt(
            Nonce::from_slice(&stable_nonce_bytes),
            Payload {
                msg: &payload,
                aad: &receiver.signature,
            },
        )
        .map_err(|e| AloecryptSessionError::RecvDecryptError(e))?;

    let session_decrypt_payload = session_cipher
        .decrypt(
            Nonce::from_slice(&session_nonce_bytes),
            Payload {
                msg: &stable_decrypt_payload,
                aad: &sender.signature,
            },
        )
        .map_err(|e| AloecryptSessionError::RecvDecryptError(e))?;

    Ok(session_decrypt_payload)
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
