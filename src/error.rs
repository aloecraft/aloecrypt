// src/error.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use chacha20poly1305::Error as ChaChaError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AloecryptSessionError {
    #[error("Received address does not match session address")]
    AddressMismatch,
    #[error("Session HELLO data missing")]
    MissingHELLO,
    #[error("Session SYN data missing")]
    MissingSYN,
    #[error("Error attempting to generate KEM with incomplete data")]
    IncompleteKEMData,
    #[error("Error encapsulating session shared secrets")]
    EncapsulateError,
    #[error("Error decapsulating session shared secrets")]
    DecapsulateError,
    #[error("Error self signature not signed")]
    SelfCipherNotSignedError,
    #[error("Error validating session counterpart signature")]
    SignatureValidationError,
    #[error("Error encrypting message")]
    SendEncryptError(ChaChaError),
    #[error("Error decrypting message")]
    RecvDecryptError(ChaChaError),
    #[error("Error decrypting handshake cipher challenge")]
    CipherTestError,
    #[error("Error: Cipher not yet created for session")]
    CipherNotReady,
    #[error("Error PartyINTRO not yet received for counter party")]
    NoCounterPartyINTRO,
    #[error("Error PartyCIPHER not yet received for counter party")]
    NoCounterPartyCIPHER,
    #[error("Error PartyCHALLENGE not yet received for counter party")]
    NoCounterPartyCHALLENGE,
    #[error("Error PartyCHALLENGE did not contain a valid check")]
    CounterPartyCheckMismatch,
    #[error("Error PartyRESPONSE did not contain a valid challenge response")]
    CounterPartyChallengeMismatch,
    #[error("Error SessionBuilder not ready")]
    BuildNotReady,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AloecryptError {
    #[error("Invalid Ed25519 public key: point decompression failed")]
    InvalidPublicKey,

    #[error("AEAD cipher operation failed")]
    Cipher(ChaChaError),

    #[error("Invalid PEM format or corrupted data")]
    InvalidPemFormat,

    #[error("Invalid PEM format or corrupted data")]
    InvalidPemTags,

    #[error("Invalid PEM format or corrupted data")]
    InvalidPemLength,

    #[error("Serialization/Deserialization failed")]
    Serialization,

    #[error("Compression/Decompression failed")]
    Compression,

    #[error("Signature Verification failed")]
    Signature,

    #[error("Password Encryption Failed")]
    PasswordEncrypt,

    #[error("Password Decryption Failed")]
    PasswordDecrypt,

    #[error("Private Key Hash Did Not Match Loaded PEM")]
    LoadPEMPrivKeyHash,

    #[error("Hash Did Not Match Loaded PEM")]
    LoadPEMHash,
}

// Manually implement From to bypass the std::error::Error trait bound requirement for the AEAD error
impl From<ChaChaError> for AloecryptError {
    fn from(err: ChaChaError) -> Self {
        AloecryptError::Cipher(err)
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
