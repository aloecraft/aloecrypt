use hex_literal::hex;
use std::mem;
pub const KEY_ITERS: u32 = 4096;
pub const COM_STRUCT_ID: &str = "AloeBuffer.0";
pub const KYBER_CANONICAL_SEED: &str = "AloecryptKyber.0";
pub const KYBER_CANONICAL_SALT: &str = "AloecryptKyber.1";
pub const MAGIC_BYTES: [u8; 16] = [
    0x41, 0x4c, 0x4f, 0x45, 0x43, 0x52, 0x59, 0x50, 0x54, 0x69, 0x61, 0x6d, 0x6d, 0x69, 0x6b, 0x65,
];

pub const PUBLIC_ADDR_PEM_TAG: &str = "ALOECRYPT PUBLIC ADDR";
pub const ROOT_ADDR_PEM_TAG: &str = "ALOECRYPT ROOT ADDR";
pub const ROOT_KEY_PEM_TAG: &str = "ALOECRYPT ROOT KEY";
pub const PEER_KYBER_PEM_TAG: &str = "ALOECRYPT PEER KYBER";
pub const KYBER_KEY_PEM_TAG: &str = "ALOECRYPT KYBER KEY";
pub const PEM_CHUNK_SZ: usize = 32;
pub const HASH_SZ: usize = 32; // HMAC
pub const ADDRESS_SZ: usize = 32; // HMAC
pub const VERIFY_KEY_SZ: usize = 1952; // DILITHIUM pubkey
pub const SIGN_KEY_SZ: usize = 4032; // DILITHIUM privkey
pub const ENCRYPTED_SIGN_KEY_SZ: usize = SIGN_KEY_SZ + ENCRYPTED_TAG_SZ;
pub const SIGNATURE_SZ: usize = 3309; // DILITHIUM signature
pub const ENCAPSULATE_KEY_SZ: usize = 1184; // KYBER pubkey
pub const DECAPSULATE_KEY_SZ: usize = 2400; // KYBER privkey
pub const ENCRYPTED_DECAPSULATE_KEY_SZ: usize = DECAPSULATE_KEY_SZ + ENCRYPTED_TAG_SZ;
pub const PQC_SEED_SZ: usize = 64;
pub const CIPHER_SZ: usize = 1088;
pub const SECRET_SZ: usize = 32;
pub const TIMESTAMP_SZ: usize = 8;
pub const CHACHA_NONCE_SZ: usize = 12;
pub const CHACHA_KEY_SZ: usize = 32;
pub const SESSION_NONCE_SZ: usize = 32;
pub const SESSION_SALT_SZ: usize = 32;
pub const SESSION_SALT_HASH_ITERS: u32 = 512;
pub const ENCRYPTED_TAG_SZ: usize = 16; // CHACHA20POLY1305
pub const ENCRYPTED_NONCE_SZ: usize = SESSION_NONCE_SZ + 2 * ENCRYPTED_TAG_SZ;

pub const U32_SZ: usize = mem::size_of::<u32>();
pub const U64_SZ: usize = mem::size_of::<u64>();

pub const EMPTY_CRYPT_KEY: [u8; CHACHA_KEY_SZ] = [0u8; CHACHA_KEY_SZ];
pub const EMPTY_CRYPT_NONCE: [u8; CHACHA_NONCE_SZ] = [0u8; CHACHA_NONCE_SZ];

pub const EMPTY_VERIFY_KEY: [u8; VERIFY_KEY_SZ] = [0u8; VERIFY_KEY_SZ];
pub const EMPTY_SIGN_KEY: [u8; SIGN_KEY_SZ] = [0u8; SIGN_KEY_SZ];
pub const EMPTY_ENCRYPTED_SIGN_KEY: [u8; ENCRYPTED_SIGN_KEY_SZ] = [0u8; ENCRYPTED_SIGN_KEY_SZ];

pub const EMPTY_ENCAPSULATE_KEY: [u8; ENCAPSULATE_KEY_SZ] = [0u8; ENCAPSULATE_KEY_SZ];
pub const EMPTY_DECAPSULATE_KEY: [u8; DECAPSULATE_KEY_SZ] = [0u8; DECAPSULATE_KEY_SZ];
pub const EMPTY_ENCRYPTED_DECAPSULATE_KEY: [u8; ENCRYPTED_DECAPSULATE_KEY_SZ] =
    [0u8; ENCRYPTED_DECAPSULATE_KEY_SZ];

pub const EMPTY_SESSION_NONCE: [u8; SESSION_NONCE_SZ] = [0u8; SESSION_NONCE_SZ];
pub const EMPTY_SESSION_SALT: [u8; SESSION_SALT_SZ] = [0u8; SESSION_SALT_SZ];
pub const EMPTY_SECRET: [u8; SECRET_SZ] = [0u8; SECRET_SZ];
pub const EMPTY_SIGNATURE: [u8; SIGNATURE_SZ] = [0u8; SIGNATURE_SZ];
pub const EMPTY_ADDRESS: [u8; ADDRESS_SZ] = [0u8; ADDRESS_SZ];
pub const EMPTY_TIMESTAMP: [u8; TIMESTAMP_SZ] = [0u8; TIMESTAMP_SZ];
pub const EMPTY_CIPHER: [u8; CIPHER_SZ] = [0u8; CIPHER_SZ];
pub const EMPTY_HASH: [u8; HASH_SZ] = [0u8; HASH_SZ];

pub const HASH_SEED_DLT_PUBKEY: &str = "AloecryptDltPubKey.0";
pub const HASH_SEED_DLT_PRIVKEY: &str = "AloecryptDltPrivKey.0";
pub const HASH_SEED_KYB_PUBKEY: &str = "AloecryptKybPubKey.0";
pub const HASH_SEED_KYB_PRIVKEY: &str = "AloecryptKybPrxxivKey.0";
pub const HASH_SEED_DLT_X_SIGNER: &str = "AloecryptDltXSigner.0";
pub const HASH_SEED_DLT_SIGNER: &str = "AloecryptDltSigner.10";
pub const HASH_SEED_DLT_VERIFIER: &str = "AloecryptDltVerifier.10";
pub const HASH_SEED_KYB_FULLKEM: &str = "AloecryptKybFullKEM.10";
pub const HASH_SEED_KYB_X_FULLKEM: &str = "AloecryptKybXFullKEM.10";
pub const HASH_SEED_KYB_PUBKEM: &str = "AloecryptKybPubKEM.10";

pub const HASH_SEED_PARTY_INTRO: &str = "AloecryptPARTY_INTRO.001";
pub const HASH_SEED_PARTY_CIPHER: &str = "AloecryptPARTY_CIPHER.001";
pub const HASH_SEED_FULL_CIPHER: &str = "AloecryptFULL_CIPHER.001";
pub const HASH_SEED_COUNTER_PARTY_SECRET: &str = "AloecryptCOUNTER_PARTY_SECRET.001";
pub const HASH_SEED_PARTY_CHALLENGE: &str = "AloecryptPARTY_CHALLENGE.001";
pub const HASH_SEED_PARTY_RESPONSE: &str = "AloecryptPARTY_RESPONSE.001";
pub const HASH_SEED_COUNTER_PARTY_CHALLENGE: &str = "AloecryptCOUNTER_PARTY_CHALLENGE.001";
pub const HASH_SEED_FROM_SECRETS_INPUT: &str = "AloecryptFROM_SECRETS_INPUT.001";
pub const HASH_SEED_SESSION_BUILDER: &str = "AloecryptSESSION_BUILDER.001";
pub const HASH_SEED_MSG_HELLO: &str = "AloecryptMSG_HELLO.001";
pub const HASH_SEED_MSG_SYN: &str = "AloecryptMSG_SYN.001";
pub const HASH_SEED_MSG_ACK: &str = "AloecryptMSG_ACK.001";
pub const HASH_SEED_MSG_SYNACK: &str = "AloecryptMSG_SYNACK.001";
pub const HASH_SEED_MSG_WELCOME: &str = "AloecryptMSG_WELCOME.001";
pub const HASH_SEED_PARTY: &str = "AloecryptPARTY.001";
pub const HASH_SEED_COUNTER_PARTY: &str = "AloecryptCOUNTER_PARTY.001";
pub const HASH_SEED_SESSION: &str = "AloecryptSESSION.001";
pub const HASH_SEED_SESSION_PRIV: &str = "AloecryptSESSION_PRIV.001";
pub const HASH_SEED_X_SESSION: &str = "AloecryptX_SESSION.001";

pub const ADDRESS_SEED_DLT_SIGNER: &str = "AloecryptDltSigner.0";
pub const ADDRESS_SEED_DLT_VERIFIER: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptDltVerifier.0";
pub const ADDRESS_SEED_KYB_FULLKEM: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptKybFullKEM.0";
pub const ADDRESS_SEED_KYB_X_FULLKEM: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptKybXFullKEM.0";
pub const ADDRESS_SEED_KYB_PUBKEM: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptKybPubKEM.0";

pub const ADDRESS_SEED_SESSION: &str = "AloecryptSession.0";
pub const ADDRESS_SEED_SESSION_BUILDER: &str = "AloecryptSessionBuilder.0";
pub const ADDRESS_SEED_PARTY: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptParty.0";
pub const ADDRESS_SEED_COUNTER_PARTY: &str = ADDRESS_SEED_DLT_SIGNER; // "AloecryptCounterParty.0";

pub const SESSION_PEM_TAG: &str = "Aloecrypt Session";
pub const MSG_HELLO_PEM_TAG: &str = "Aloecrypt MsgHELLO";
pub const MSG_SYN_PEM_TAG: &str = "Aloecrypt MsgSYN";
pub const MSG_ACK_PEM_TAG: &str = "Aloecrypt MsgACK";
pub const MSG_SYNACK_PEM_TAG: &str = "Aloecrypt MsgSYNACK";
pub const MSG_WELCOME_PEM_TAG: &str = "Aloecrypt MsgWELCOME";
pub const MSG_GOODBYE_PEM_TAG: &str = "Aloecrypt MsgGOODBYE";
pub const MSG_RETRY_PEM_TAG: &str = "Aloecrypt MsgRETRY";
pub const MSG_RESYN_PEM_TAG: &str = "Aloecrypt MsgRESYN";

pub const SESSION_SALT_INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");
pub const SESSION_CHACHA_KEY_INFO: [u8; 10] = hex!("e0f1f2f3f4f5f6f7f8f9");
pub const SESSION_CHACHA_NONCE_INFO: [u8; 10] = hex!("d0f1f2f3f4f5f6f7f8f9");
pub const SESSION_MSG_NONCE_INFO: [u8; 10] = hex!("c0f1f2f3f4f5f6f7f8f9");

pub const STABLE_SALT_INFO: [u8; 10] = hex!("f1f1f2f3f4f5f6f7f8f9");
pub const STABLE_CHACHA_KEY_INFO: [u8; 10] = hex!("e1f1f2f3f4f5f6f7f8f9");
pub const STABLE_CHACHA_NONCE_INFO: [u8; 10] = hex!("d1f1f2f3f4f5f6f7f8f9");
pub const STABLE_MSG_NONCE_INFO: [u8; 10] = hex!("c1f1f2f3f4f5f6f7f8f9");

pub const NONCE_SYN_STABLE_SEED: &str = "AloecryptSYN.0";
pub const NONCE_SYN_SESSION_SEED: &str = "AloecryptSYN.1";
pub const NONCE_ACK_STABLE_SEED: &str = "AloecryptACK.0";
pub const NONCE_ACK_SESSION_SEED: &str = "AloecryptACK.1";
pub const NONCE_SYNACK_STABLE_SEED: &str = "AloecryptSYNACK.0";
pub const NONCE_SYNACK_SESSION_SEED: &str = "AloecryptSYNACK.1";

pub const NONCE_MSG_STABLE_SEED: &str = "AloecryptMSG.0";
pub const NONCE_MSG_SESSION_SEED: &str = "AloecryptMSG.1";
