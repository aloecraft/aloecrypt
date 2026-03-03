# aloecrypt

<div align="center">

<img src="doc/icon.png" style="height:96px; width:96px;"/>

**A Fast Secure Format For File Sharing And Encryption At Rest**

[![GitHub](https://img.shields.io/badge/GitHub-%23121011.svg?logo=github&logoColor=white)](https://github.com/aloecraft/aloecrypt)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

</div>

## What It Is

Aloecrypt is a binary packaging format and CLI tool for encrypting, signing, and exchanging files between Ed25519 identity holders. A package (`.alo` file) contains three sections:

- **Header** (176 bytes): magic bytes, recipient address, sender public key, app ID, nonce, and an Ed25519 signature over the encrypted payload
- **Payload**: the input data, serialized with MessagePack, compressed with LZ4, then encrypted with ChaCha20-Poly1305 using an X25519 shared secret
- **Footer**: compressed MessagePack metadata (description, timestamps, arbitrary key-value pairs)

Identities are Ed25519 keypairs with a UUIDv7 CID. Private keys are stored in password-protected keyfiles (PBKDF2 + ChaCha20-Poly1305). The format converts Ed25519 keys to X25519 for Diffie-Hellman key exchange, so a single identity handles both signing and encryption.

## Installation

```bash
cargo install --path .
```

## Usage

### Generate a keyfile

```bash
aloecrypt key new -o alice.pem -p mypassword
aloecrypt key new -o bob.pem -p otherpassword
```

### Get a public key (for sharing or scripts)

```bash
aloecrypt key pubkey -k alice.pem
```

### Encrypt and pack a file

```bash
BOB_PUB=$(aloecrypt key pubkey -k bob.pem)
aloecrypt pack secret.json "$BOB_PUB" "MY_APP_ID" -k alice.pem -o package.alo
```

### Decrypt and verify a package

```bash
ALICE_PUB=$(aloecrypt key pubkey -k alice.pem)
aloecrypt unpack package.alo "$ALICE_PUB" -k bob.pem -o decrypted.json
```

The second positional argument to `unpack` is optional. If provided, the tool rejects the package unless the signer matches. If omitted, it prints the signer's public key to stderr after verification.

### Other key operations

```bash
aloecrypt key info -k alice.pem          # show CID and public key (requires password)
aloecrypt key setpw -k alice.pem -o new.pem  # re-encrypt with a new password
```

## Library Usage

Aloecrypt is also a Rust library. The core types are `Keypair`, `PeerKey`, `Keyfile`, and `AloecryptPackage`.

```rust
use aloecrypt::keypair::Keypair;
use aloecrypt::aloecrypt::AloecryptPackage;
use aloecrypt::{PrivKey, KeyPEM};

let alice = Keypair::new();
let bob = Keypair::new();

let nonce = [0u8; 16]; // use random in practice
let app_id = b"[MY_APP_ID_HERE]";

let package = AloecryptPackage::pack(
    &"hello world".to_string(),
    &alice,
    &bob.public_key,
    app_id,
    &nonce,
).unwrap();

let wire_bytes = package.to_bytes().unwrap();

let reloaded = AloecryptPackage::from_bytes(&wire_bytes).unwrap();
assert!(reloaded.verify_hdr());

let msg: String = reloaded.unpack(&bob).unwrap();
```

## Wire Format

```
[Header: 176 bytes][Encrypted Payload: variable][Footer: variable]

Header layout:
  [0..16]    Magic bytes (ALOECRYPTiammike)
  [16..48]   Recipient public key (32 bytes)
  [48..80]   Signer public key (32 bytes)
  [80..96]   Application ID (16 bytes)
  [96..112]  Nonce (16 bytes)
  [112..176] Ed25519 signature (64 bytes)

Footer layout (from end of file):
  [...-N]    LZ4-compressed MessagePack data
  [-N..-18]  Footer length (2 bytes, little-endian)
  [-18..end] Magic bytes (16 bytes)
```

## Cryptographic Details

| Operation | Algorithm |
|---|---|
| Identity keys | Ed25519 (signing) → X25519 (key exchange) |
| Key exchange | X25519 Diffie-Hellman |
| Symmetric encryption | ChaCha20-Poly1305 |
| Key derivation | PBKDF2-HMAC-SHA256 (4096 rounds) |
| Keyfile encryption | PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305 |
| Self-encryption | PBKDF2-HMAC-SHA512 + ChaCha20-Poly1305 |
| Serialization | MessagePack (rmp-serde) |
| Compression | LZ4 (frame format) |

## License

Apache 2.0