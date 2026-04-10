// src/kem/decapsulator.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

impl AloecryptDecapsulator for KyberFullKEM {
    fn decapsulation_key(&self) -> KyberPrivkey {
        self.kyb_privkey
    }

    fn decapsulate(&self, cipher: KyberCipher) -> AloecryptSecret {
        DecapsulationKey::<MlKem768>::from_expanded(&self.kyb_privkey.into())
            .unwrap()
            .decapsulate((&cipher).into())
            .into()
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
