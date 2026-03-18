# aloecrypt

<div align="center">

<img src="https://raw.githubusercontent.com/aloecraft/aloecrypt/refs/heads/main/doc/icon.png" style="height:96px; width:96px;"/>

**Post-Quantum Cryptographic Identity, Key Encapsulation, and Secure Sessions**

[![GitHub](https://img.shields.io/badge/GitHub-%23121011.svg?logo=github&logoColor=white)](https://github.com/aloecraft/aloecrypt)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

</div>

## What It Is

Aloecrypt is a Rust library for post-quantum identity management, key encapsulation, and authenticated session establishment. It provides:

- **ML-DSA-65 (Dilithium) signing** with a hierarchical delegation model — root signers authorize delegate signers with scoped validity
- **ML-KEM-768 (Kyber) key encapsulation** — both deterministic (canonical) and random KEM generation, signed by the owning identity
- **A five-message session handshake** (HELLO → SYN → ACK → SYNACK → WELCOME) that establishes a double-KEM shared secret with mutual challenge/response authentication
- **Double-layer ChaCha20Poly1305 encryption** — each message passes through a session-key cipher then a stable-key cipher, derived independently via HKDF
- **Password-protected PEM storage** for signers, KEM bundles, and complete sessions (PBKDF2 + ChaCha20Poly1305 with hash-based integrity verification)
- **Cross-platform support** — builds for native targets and browser WASM (`wasm32-unknown-unknown`)

## Library Usage

### Create an Identity

```rust
use aloecrypt::signatory::DilithiumSigner;
use aloecrypt::traits::*;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

let mut seed = [0u8; 32];
getrandom::getrandom(&mut seed);
let mut rng = ChaCha20Rng::from_seed(seed);

// Root signer — the long-lived identity
let root = DilithiumSigner::new(&mut rng);

// Delegate signer — scoped for a specific purpose
let delegate = root.create_dilithium_signer(
    &mut rng,
    EMPTY_TIMESTAMP, // active_from
    EMPTY_TIMESTAMP, // expires_at
    0, 0,            // refresh_count, max_refresh
);
```

### Establish a Session

```rust
use aloecrypt::session::builder::SessionBuilder;
use aloecrypt::session::message::*;
use aloecrypt::traits::*;

// Both parties create session builders
let mut builder_a = SessionBuilder::new(party_b_address, delegate_a, &mut rng);
let mut builder_b = SessionBuilder::new(party_a_address, delegate_b, &mut rng);

// A → B: HELLO (send intro)
let hello = MsgHELLO { address: builder_a.address(), intro: builder_a.make_party_intro() };
builder_b.on_counterparty_intro(&hello.intro, &mut rng)?;

// B → A: SYN (intro + cipher)
let syn = MsgSYN {
    syn_to: builder_b.counterparty_intro.unwrap().nonce,
    syn_address: builder_b.address(),
    intro: builder_b.make_party_intro(),
    cipher: builder_b.make_party_cipher()?,
};
builder_a.on_counterparty_intro(&syn.intro, &mut rng)?;
builder_a.on_counterparty_cipher(syn.cipher)?;

// A → B: ACK (cipher + challenge)
// B → A: SYNACK (challenge + response)
// A → B: WELCOME (response)
// ... (see tests/handshake.rs for the complete flow)

let session_a = builder_a.build()?;
let session_b = builder_b.build()?;
```

### Encrypt and Decrypt

```rust
// A → B
let ciphertext = session_a.encrypt(b"Hello from A!")?;
let plaintext = session_b.decrypt(&ciphertext)?;

// B → A
let ciphertext = session_b.encrypt(b"Hello back from B!")?;
let plaintext = session_a.decrypt(&ciphertext)?;
```

### Build a Session from Pre-Shared Secrets

For testing or integration with external key agreement, sessions can be constructed directly:

```rust
use aloecrypt::session::session::AloecryptSession;

let session = AloecryptSession::from_secrets(
    party_stable_secret, party_session_secret, party_signature,
    party_nonce, party_address,
    counter_stable_secret, counter_session_secret, counter_signature,
    counter_nonce, counter_address,
    session_salt,
);
```

### PEM Export and Import

All private types support password-protected PEM serialization:

```rust
// Export
let pem = signer.x_pem(b"password", b"salt", &mut rng);

// Import (full key)
let loaded = DilithiumSigner::x_loads(&pem, b"password", b"salt")?;

// Import (public portion only — no password needed)
let verifier = DilithiumSigner::x_pub_loads(&pem)?;
```

Sessions also round-trip through PEM:

```rust
let session_pem = session.x_pem(b"password", b"salt", &mut rng);
let loaded = AloecryptSession::x_loads(&session_pem, b"password", b"salt")?;
```

## Handshake Protocol

```
Party A                              Party B
   |                                    |
   |──── HELLO (intro) ───────────────>│
   |                                    |
   │<─── SYN (intro + cipher) ─────────|
   |                                    |
   |──── ACK (cipher + challenge) ────>│
   |                                    |
   │<─── SYNACK (challenge + response) │
   |                                    |
   |──── WELCOME (response) ──────────>│
   |                                    |
   |     [ session established ]        |
```

Each party contributes a stable KEM and a session KEM. The handshake produces four independent shared secrets (two per KEM, one from each direction) which are combined via HKDF to derive the session encryption keys. Challenge/response nonces verify both parties can correctly encrypt and decrypt before the session is finalized.

## Encryption Architecture

Messages are encrypted through two independent ChaCha20Poly1305 layers:

1. **Session cipher** — keyed from the session KEM shared secret, uses the sender's signature as AAD
2. **Stable cipher** — keyed from the stable KEM shared secret, wraps the session-encrypted payload with the receiver's signature as AAD

Nonces and cipher keys are derived via HKDF with domain-separated info tags. Cipher salts incorporate the session salt, nonces, and addresses of both parties to ensure uniqueness.

## Cryptographic Details

| Component | Algorithm |
|---|---|
| Signatures | ML-DSA-65 (Dilithium) |
| Key encapsulation | ML-KEM-768 (Kyber) |
| Symmetric encryption | ChaCha20Poly1305 (double-layered) |
| Key derivation (session) | HKDF-SHA256 |
| Key derivation (password) | PBKDF2-HMAC-SHA256 (4096 rounds) |
| Addressing | HKDF-SHA256 with domain-separated seeds |
| Hashing | HKDF-SHA256 with domain-separated seeds |

## Cross-Platform

Aloecrypt builds for native targets and `wasm32-unknown-unknown`. Platform-specific handling includes:

- Time: `std::time` on native, `instant` crate on WASM
- RNG: `getrandom` with `js` feature on WASM
- UUID: `uuid` with `js` feature on WASM

## License

Apache 2.0