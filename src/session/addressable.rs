// src/session/addressable.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::builder::*;
use super::message::*;
use super::party::*;
use super::session::*;
use super::*;
use crate::util::_address;

// impl AloecryptAddressable for PartyINTRO {         }
// impl AloecryptAddressable for PartyCIPHER {        }
// impl AloecryptAddressable for FullCIPHER {         }

// impl AloecryptAddressable for PartySecret {        }
// impl AloecryptAddressable for PartyCHALLENGE {     }
// impl AloecryptAddressable for PartyRESPONSE {      }
// impl AloecryptAddressable for PartyChallenge {     }
// impl AloecryptAddressable for FromSecretsInput {   }

// impl AloecryptAddressable for MsgHELLO {           }
// impl AloecryptAddressable for MsgSYN {             }
// impl AloecryptAddressable for MsgACK {             }
// impl AloecryptAddressable for MsgSYNACK {          }
// impl AloecryptAddressable for MsgWELCOME {         }

impl AloecryptAddressable for Party {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.delegate_signer.generation()
    }
    fn address(&self) -> AloecryptAddress {
        self.delegate_signer.address()
    }
    fn root_address(&self) -> AloecryptAddress {
        self.delegate_signer.root_address()
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.delegate_signer.addressing_material()
    }
}

impl AloecryptAddressable for CounterParty {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.verifier.generation()
    }
    fn address(&self) -> AloecryptAddress {
        self.verifier.address()
    }
    fn root_address(&self) -> AloecryptAddress {
        self.verifier.root_address()
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.verifier.addressing_material()
    }
}

impl AloecryptAddressable for SessionBuilder {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.delegate_signer.generation()
    }
    fn address(&self) -> AloecryptAddress {
        self.delegate_signer.address()
    }
    fn root_address(&self) -> AloecryptAddress {
        self.delegate_signer.root_address()
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.delegate_signer.addressing_material()
    }
}

impl AloecryptAddressable for AloecryptSession {
    fn is_root(&self) -> bool {
        self.generation() == 0
    }
    fn generation(&self) -> u64 {
        self.party.delegate_signer.generation()
    }
    fn address(&self) -> AloecryptAddress {
        self.party.delegate_signer.address()
    }
    fn root_address(&self) -> AloecryptAddress {
        self.party.root_address()
    }
    fn addressing_material(&self) -> Vec<u8> {
        self.party.delegate_signer.addressing_material()
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
