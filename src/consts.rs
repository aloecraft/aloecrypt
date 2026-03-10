use hex_literal::hex;

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
pub const ADDRESS_SZ: usize = 32; // HMAC
pub const VERIFY_KEY_SZ: usize = 1952; // DILITHIUM pubkey
pub const SIGN_KEY_SZ: usize = 4032; // DILITHIUM privkey
pub const SIGNATURE_SZ: usize = 3309; // DILITHIUM signature
pub const ENCAPSULATE_KEY_SZ: usize = 1184; // KYBER pubkey
pub const DECAPSULATE_KEY_SZ: usize = 2400; // KYBER privkey
pub const CIPHER_SZ: usize = 1088;
pub const SECRET_SZ: usize = 32;
pub const TIMESTAMP_SZ: usize = 8;
pub const CHACHA_NONCE_SZ: usize = 12;
pub const SESSION_NONCE_SZ: usize = 32;
pub const SESSION_SALT_SZ: usize = 32;
pub const SESSION_SALT_HASH_ITERS: u32 = 512;
pub const ENCRYPTED_TAG_SZ: usize = 16; // CHACHA20POLY1305
pub const ENCRYPTED_NONCE_SZ: usize = SESSION_NONCE_SZ + 2 * ENCRYPTED_TAG_SZ;
pub const EMPTY_SIGNATURE: [u8; SIGNATURE_SZ] = [0u8; SIGNATURE_SZ];
pub const EMPTY_ADDRESS: [u8; ADDRESS_SZ] = [0u8; ADDRESS_SZ];
pub const EMPTY_TIMESTAMP: [u8; TIMESTAMP_SZ] = [0u8; TIMESTAMP_SZ];

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

