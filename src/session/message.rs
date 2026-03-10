use crate::kem::{KyberFullKEM, KyberPublicKEM};
use crate::signatory::{DilithiumSigner, DilithiumVerifier};
use crate::consts::*;
use crate::error::*;
use crate::session::util::{nonce_pair, cipher_pair, cipher_salt};
use crate::session::builder::{PartyINTRO, PartyCIPHER, PartyCHALLENGE, PartyRESPONSE, PartySecret, PartyChallenge, FullCIPHER};

use chacha20poly1305::Nonce;
use chacha20poly1305::aead::{Aead, Payload};

#[derive(Clone)]
pub struct MsgHELLO {
    pub address: [u8; ADDRESS_SZ],
    pub intro: PartyINTRO
}

#[derive(Clone)]
pub struct MsgSYN {
    pub intro: PartyINTRO,
    pub cipher: PartyCIPHER
}

#[derive(Clone)]
pub struct MsgACK {
    pub cipher: PartyCIPHER,
    pub challenge: PartyCHALLENGE
}

#[derive(Clone)]
pub struct MsgSYNACK {
    pub challenge: PartyCHALLENGE,
    pub challenge_response: PartyRESPONSE,
}

#[derive(Clone)]
pub struct MsgWELCOME {
    pub challenge_response: PartyRESPONSE,
}

pub fn send_encrypt(
    payload: &[u8],
    sender: FullCIPHER,
    receiver: PartySecret,
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
    // println!("receiver_salt: {:x?}", receiver_salt);
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
    sender: PartySecret,
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
    // println!("receiver_salt: {:x?}", receiver_salt);
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
