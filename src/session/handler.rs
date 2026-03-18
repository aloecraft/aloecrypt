// src/session/handler.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::*;

// enum AloecryptSessionMsg {
//     HELLO {
//         address: AloecryptAddress,  // <-- i.e. "This is the address I intend to use to call you"
//         intro: PartyINTRO,   // <-- i.e. "This is my info"
//     },
//     SYN {
//         syn_to: [u8; SESSION_NONCE_SZ], // <-- [New] i.e. "Here's your nonce from your intro (these need to match so we both compute the same session salt)"
//         syn_address: [u8; ADDRESS_SZ], // <-- [New] i.e. "Call me by this"
//         intro: PartyINTRO, // <-- i.e. "This is my info"
//         cipher: PartyCIPHER, // <-- i.e. This is the first step in constructing ciphers
//     },
//     ACK {
//         ack_to: [u8; SESSION_NONCE_SZ],  // <-- [New] i.e. "Here's your nonce from your intro (these need to match so we both compute the same session salt)"
//         ack_address: [u8; ADDRESS_SZ],  // <-- [New] i.e. acknowledge: "Ok, I'll call you by this"
//         cipher: PartyCIPHER, // <-- i.e. Here's my part of the cipher
//         challenge: PartyCHALLENGE,  // <-- i.e. Here's a challenge constructed from your cipher (with a check so you can confirm that I'm sending properly)
//     },
//     SYNACK {
//         syn_ack: [u8; SESSION_SALT_SZ], // <-- [New] i.e. "Here's that mutually computed salt"
//         challenge: PartyCHALLENGE, // <-- i.e. Here's a challenge constructed from your cipher (with a check so you can confirm that I'm sending properly)
//         challenge_response: PartyRESPONSE, // i.e. Here' my answer to your challenge. Is this right?
//     },
//     WECLOME {
//         session_salt: [u8; SESSION_SALT_SZ], // <-- [New] i.e. "Here's that mutually computed salt"
//         challenge_response: PartyRESPONSE,  // i.e. Here' my answer to your challenge. (you can send a retry or goodbye if there's an issue)
//     },
//     TRANSPORT {
//         session_salt: [u8; SESSION_SALT_SZ],
//         payload: [u8],
//     },
//     ROTATE {
//         session_salt: [u8; SESSION_SALT_SZ],
//         syn_to: [u8; SESSION_NONCE_SZ],
//         syn_address: [u8; ADDRESS_SZ],
//         cipher: PartyCIPHER, // i.e. "This is my new cipher"
//     },
//     RESYN {
//         address: AloecryptAddress,
//         intro: PartyINTRO,
//     },
//     GOODBYE {
//         address: AloecryptAddress,
//         session_salt: [u8; SESSION_SALT_SZ],
//     },
//     RETRY {
//         address: AloecryptAddress,
//         wait_ms: u64,
//     },
//     ERROR {
//         address: AloecryptAddress,
//     },
// }
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
