// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the "License");
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
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};

use crate::error::AloecryptError;

/// Converts a 32-byte Ed25519 public key to a 32-byte X25519 public key.
pub fn to_curve25519_public_key(ed25519_pub_bytes: &[u8; 32]) -> Result<[u8; 32], AloecryptError> {
    let edwards_y = CompressedEdwardsY(*ed25519_pub_bytes);
    let edwards_point = edwards_y
        .decompress()
        .ok_or(AloecryptError::InvalidPublicKey)?;
    Ok(edwards_point.to_montgomery().to_bytes())
}

/// Converts a 32-byte Ed25519 private key to a 32-byte X25519 private key.
pub fn to_curve25519_private_key(ed25519_priv_bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(ed25519_priv_bytes);
    let hash_output = hasher.finalize();

    let mut x_priv_scalar = [0u8; 32];
    x_priv_scalar.copy_from_slice(&hash_output[..32]);

    // Clamping: Necessary for X25519 interop
    x_priv_scalar[0] &= 248;
    x_priv_scalar[31] &= 127;
    x_priv_scalar[31] |= 64;

    x_priv_scalar
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    #[test]
    fn test_valid_public_key_conversion() {
        // 1. Generate a real Ed25519 keypair
        let mut csprng = OsRng;
        let ed_signing_key = SigningKey::generate(&mut csprng);
        let ed_verifying_key = ed_signing_key.verifying_key();

        // 2. Convert the public key using our function
        let x_pub_bytes = to_curve25519_public_key(ed_verifying_key.as_bytes())
            .expect("Valid Ed25519 public key should decompress successfully");

        // 3. Verify it's a valid X25519 public key structure
        let _x_pub = X25519PublicKey::from(x_pub_bytes);
    }

    #[test]
    fn test_invalid_public_key_conversion() {
        let mut invalid_pub_bytes = [0u8; 32];
        for i in 0..=255 {
            invalid_pub_bytes[0] = i;
            if to_curve25519_public_key(&invalid_pub_bytes).is_err() {
                break;
            }
        }
        let result = to_curve25519_public_key(&invalid_pub_bytes);
        assert_eq!(result, Err(AloecryptError::InvalidPublicKey));
    }

    #[test]
    fn test_private_key_conversion_matches_public_key() {
        let mut csprng = OsRng;
        let ed_signing_key = SigningKey::generate(&mut csprng);

        // 1. Convert the private key
        let x_priv_bytes = to_curve25519_private_key(&ed_signing_key.to_bytes());
        let x_static_secret = StaticSecret::from(x_priv_bytes);

        // 2. Derive the X25519 public key directly from the converted private key
        let derived_x_pub = X25519PublicKey::from(&x_static_secret);

        // 3. Convert the original Ed25519 public key using our other function
        let ed_pub_bytes = ed_signing_key.verifying_key().to_bytes();
        let converted_x_pub_bytes = to_curve25519_public_key(&ed_pub_bytes).unwrap();

        // 4. They should match perfectly (The fundamental theorem of this key conversion)
        assert_eq!(derived_x_pub.as_bytes(), &converted_x_pub_bytes);
    }
}
