// src/signatory/empty.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::kem::KyberFullKEM;
use crate::kem::KyberPublicKEM;
use crate::signatory::DilithiumSigner;
use crate::signatory::DilithiumVerifier;
use crate::traits::*;
use crate::types::*;

use crate::impl_empty_default;
use crate::impl_empty_from_bytes;
use crate::impl_empty_obj;
use crate::impl_empty_size;
use crate::impl_empty_to_bytes;

impl AloecryptEmpty for XDilithiumSigner {
    impl_empty_obj!(XDilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        x_dlt_privkey:     [u8][ENCRYPTED_SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_priv_hash:     [u8][HASH_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
        un_hash:           [u8][HASH_SZ],
        nonce:             [u8][CHACHA_NONCE_SZ],
    );
    impl_empty_to_bytes!(XDilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        x_dlt_privkey:     [u8][ENCRYPTED_SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_priv_hash:     [u8][HASH_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
        un_hash:           [u8][HASH_SZ],
        nonce:             [u8][CHACHA_NONCE_SZ],
    );
    impl_empty_from_bytes!(XDilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        x_dlt_privkey:     [u8][ENCRYPTED_SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_priv_hash:     [u8][HASH_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
        un_hash:           [u8][HASH_SZ],
        nonce:             [u8][CHACHA_NONCE_SZ],
    );
}

impl AloecryptEmpty for DilithiumSigner {
    impl_empty_obj!(DilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_privkey:       [u8][SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
    impl_empty_to_bytes!(DilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_privkey:       [u8][SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
    impl_empty_from_bytes!(DilithiumSigner;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_privkey:       [u8][SIGN_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
}

impl AloecryptEmpty for DilithiumVerifier {
    impl_empty_obj!(DilithiumVerifier;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
    impl_empty_to_bytes!(DilithiumVerifier;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
    impl_empty_from_bytes!(DilithiumVerifier;
        dlt_pubkey:        [u8][VERIFY_KEY_SZ],
        dlt_root_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_auth_pubkey:   [u8][VERIFY_KEY_SZ],
        dlt_sig_bytes:     [u8][SIGNATURE_SZ],
        dlt_root_address:  [u8][ADDRESS_SZ],
        dlt_auth_address:  [u8][ADDRESS_SZ],
        dlt_created_at:    [u8][TIMESTAMP_SZ],
        dlt_active_from:   [u8][TIMESTAMP_SZ],
        dlt_expires_at:    [u8][TIMESTAMP_SZ],
        dlt_refresh_count: u32,
        dlt_max_refresh:   u32,
        dlt_generation:    u64,
    );
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
