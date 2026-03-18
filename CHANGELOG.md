# Changelog

## [0.2.x] - Unreleased
- JWT tokens
- Compact keys
- on_party_intro should accommodate syn_address and ack_address

## [0.2.0] - 2026-03-17

### Breaking Changes

- **Dropped all non-PQC cryptography.** Ed25519 signing, X25519 key exchange, and all related types have been removed. The library now uses ML-DSA-65 (Dilithium) for signatures and ML-KEM-768 (Kyber) for key encapsulation exclusively.
- **Removed the `.alo` package format.** The `AloecryptPackage`, header/footer wire format, `pack`/`unpack` CLI commands, and all associated types (`Keypair`, `PeerKey`, `Keyfile`) are gone. Aloecrypt is now a session-oriented cryptography library, not a file packaging tool.
- **Removed MessagePack serialization and LZ4 compression** as dependencies and format concerns.
- **CLI is disabled** pending redesign around the new primitives (commented out, Clap dependency removed from active use).

### Added

- **ML-DSA-65 (Dilithium) signer hierarchy.** Root signers create delegate signers with scoped validity (timestamps, generation tracking, refresh counts). Delegates can sign KEM bundles and session material but cannot self-verify — only the authorizing signer can verify a delegate's signature.
- **ML-KEM-768 (Kyber) key encapsulation.** Both canonical (deterministic, derived from signer private key via PBKDF2) and random KEM generation. Full KEM, public KEM, and encrypted (X-prefixed) variants.
- **Five-message session handshake protocol:** HELLO → SYN → ACK → SYNACK → WELCOME. Establishes a double-KEM shared secret with mutual authentication via encrypted challenge/response.
- **Double-layer symmetric encryption.** Each message is encrypted with a session-key ChaCha20Poly1305 cipher, then wrapped in a stable-key ChaCha20Poly1305 cipher, both derived via HKDF from independent KEM shared secrets.
- **`AloecryptSession::from_secrets` constructor.** Allows building a working session directly from pre-shared secrets, bypassing the handshake — useful for testing, relay-mediated session resumption, or integration with external key agreement.
- **Password-protected PEM format** for all private types: signers (`XDilithiumSigner`), KEM bundles (`XKyberFullKEM`), and complete sessions (`XAloecryptSession`). Uses PBKDF2 + ChaCha20Poly1305 with integrity verification via stored hashes.
- **Public PEM extraction** (`x_pub_loads`) — read the public portion of a password-protected PEM without the password.
- **Comprehensive hash/address traits.** HKDF-based addressing (`AloecryptAddressable`) and hashing (`AloecryptHashable`) with domain-separated seeds for every type. Encrypted types carry pre-lock hashes for integrity verification on unlock.
- **Serialization macros** (`impl_empty_obj!`, `impl_empty_to_bytes!`, `impl_empty_from_bytes!`) for deterministic binary serialization of all protocol types, including `Option`-wrapped fields.
- **Additional session messages:** `MsgGOODBYE`, `MsgRETRY`, `MsgRESYN`, `MsgROTATE`, `MsgERROR` (structs defined, handlers not yet implemented).
- **PEM round-trip for all handshake messages** (`MsgHELLO`, `MsgSYN`, `MsgACK`, `MsgSYNACK`, `MsgWELCOME`, `MsgGOODBYE`, `MsgRETRY`, `MsgRESYN`) via `impl_msg_pem!` macro.
- **Cross-platform time abstraction** (`src/time.rs`) using `instant` crate on WASM, `std::time` elsewhere.
- **Python bindings codegen** (`bin/generate.rs`) using `serde-generate` / `serde-reflection` for all public types.
- **Test suite** covering PQC signature verification, KEM encapsulate/decapsulate, PEM round-trips (including wrong-password rejection), full handshake with bidirectional messaging, custom `from_secrets` sessions, and challenge-response rejection.

### Removed

- `ed25519-dalek` and `x25519-dalek` as runtime dependencies (kept in dev-dependencies for now).
- `Keypair`, `PeerKey`, `Keyfile`, `AloecryptPackage` types.
- `pack`, `unpack`, `key new`, `key info`, `key pubkey`, `key setpw` CLI commands.
- `.alo` wire format (magic bytes, header, footer).
- X25519 Diffie-Hellman key exchange.
- PBKDF2-HMAC-SHA512 self-encryption path.

### Changed

- Bumped `ml-kem` to `0.3.0-rc.0` and `ml-dsa` to a fork resolving a memory leak in `from_seed` (branch `issue1256_mldsa_from_seed_memory_leak`).
- `getrandom` used directly instead of `OsRng` for seed generation.
- All key/signature/cipher types use fixed-size byte arrays with `serde_big_array` for serialization.
- PBKDF2 iteration count is 4096 for password-based key derivation.


``` rs
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
```