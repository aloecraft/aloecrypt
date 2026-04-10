// src/signatory/verifier.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptVerifier for DilithiumVerifier {
    fn verifying_key(&self) -> DilithiumPubkey {
        self.dlt_pubkey
    }
    fn may_verify(&self) -> bool {
        let now = _ts_bytes_now();
        now > self.dlt_active_from
    }
    fn verify(
        &self,
        signing_material: Vec<u8>,
        sig_bytes: DilithiumSignature,
    ) -> Result<(), AloecryptError> {
        let signature =
            Signature::<MlDsa65>::decode(&sig_bytes.into()).expect("Error decoding signature!");

        VerifyingKey::<MlDsa65>::decode(&self.dlt_pubkey.into())
            .verify(&(*signing_material), &signature)
            .map_err(|e| AloecryptError::Signature)
    }
}

impl AloecryptVerifier for DilithiumSigner {
    fn verifying_key(&self) -> DilithiumPubkey {
        self.dlt_pubkey
    }
    fn may_verify(&self) -> bool {
        _ts_bytes_now() > self.dlt_active_from
    }
    fn verify(
        &self,
        signing_material: Vec<u8>,
        sig_bytes: DilithiumSignature,
    ) -> Result<(), AloecryptError> {
        let signature =
            Signature::<MlDsa65>::decode(&sig_bytes.into()).expect("Error decoding signature!");
        VerifyingKey::<MlDsa65>::decode(&self.dlt_pubkey.into())
            .verify(&(*signing_material), &signature)
            .map_err(|e| AloecryptError::Signature)
    }
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
