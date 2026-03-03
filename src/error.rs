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
use chacha20poly1305::Error as ChaChaError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AloecryptError {
    #[error("Invalid Ed25519 public key: point decompression failed")]
    InvalidPublicKey,

    #[error("AEAD cipher operation failed")]
    Cipher(ChaChaError),

    #[error("Invalid PEM format or corrupted data")]
    InvalidPemFormat,

    #[error("Serialization/Deserialization failed")]
    Serialization,

    #[error("Compression/Decompression failed")]
    Compression,
}

// Manually implement From to bypass the std::error::Error trait bound requirement for the AEAD error
impl From<ChaChaError> for AloecryptError {
    fn from(err: ChaChaError) -> Self {
        AloecryptError::Cipher(err)
    }
}
