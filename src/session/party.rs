// src/session/party.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;
use crate::consts::*;
use crate::crypt::*;
use crate::kem::*;
use crate::signatory::*;
use crate::traits::*;
use crate::types::*;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Party {
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub session_signature: DilithiumSignature,
    pub delegate_signer: DilithiumSigner,
    pub stable_kem: KyberFullKEM,
    pub session_kem: KyberFullKEM,
    pub stable_secret: AloecryptSecret,
    pub session_secret: AloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct CounterParty {
    pub address: AloecryptAddress,
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
    pub stable_secret: AloecryptSecret,
    pub session_secret: AloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct XParty {
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub session_signature: DilithiumSignature,
    pub x_delegate_signer: XDilithiumSigner,
    pub x_stable_kem: XKyberFullKEM,
    pub x_session_kem: XKyberFullKEM,
    #[serde(with = "BigArray")]
    pub x_stable_secret: XAloecryptSecret,
    #[serde(with = "BigArray")]
    pub x_session_secret: XAloecryptSecret,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct XCounterParty {
    pub address: AloecryptAddress,
    pub nonce: AloecryptSessionNonce,
    #[serde(with = "BigArray")]
    pub signature: DilithiumSignature,
    pub stable_kem: KyberPublicKEM,
    pub session_kem: KyberPublicKEM,
    pub verifier: DilithiumVerifier,
    #[serde(with = "BigArray")]
    pub x_stable_secret: XAloecryptSecret,
    #[serde(with = "BigArray")]
    pub x_session_secret: XAloecryptSecret,
    pub crypt_nonce: [u8; CHACHA_NONCE_SZ],
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
