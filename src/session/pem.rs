// src/session/pem.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::session::*;
use super::*;
use crate::error::AloecryptError;

const SESSION_PEM_TAG: &str = crate::consts::SESSION_PEM_TAG;

impl AloecryptPEM for XAloecryptSession {
    fn pem_hdr_tag() -> String {
        format!("----- BEGIN {} v1 -----", SESSION_PEM_TAG)
    }
    fn pem_ftr_tag() -> String {
        format!("----- END {} v1 -----", SESSION_PEM_TAG)
    }
    fn pem_sz() -> usize {
        Self::byte_sz()
            + (Self::byte_sz() / PEM_CHUNK_SZ)
            + XAloecryptSession::pem_hdr_tag().len()
            + 1
            + XAloecryptSession::pem_ftr_tag().len()
            + 1
    }
    fn pem(&self) -> String {
        let pem_bytes = self.to_bytes();
        let mut out = format!("{}\n", XAloecryptSession::pem_hdr_tag());
        for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
            writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
        }
        out.push_str(format!("{}\n", XAloecryptSession::pem_ftr_tag()).as_str());
        out
    }
    fn loads(pem: &str) -> Result<Self, AloecryptError> {
        let stripped: String = pem.lines().map(|l| l.trim()).collect();
        if !stripped.starts_with(&XAloecryptSession::pem_hdr_tag())
            || !stripped.ends_with(&XAloecryptSession::pem_ftr_tag())
        {
            return Err(AloecryptError::InvalidPemTags);
        }
        let hex_body = &stripped[XAloecryptSession::pem_hdr_tag().len()
            ..stripped.len() - XAloecryptSession::pem_ftr_tag().len()];
        let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
        if bytes.len() != Self::byte_sz() {
            return Err(AloecryptError::InvalidPemLength);
        }
        Ok(XAloecryptSession::from_bytes(bytes))
    }
}

macro_rules! impl_msg_pem {
    ($ty:ty, $tag:expr) => {
        impl AloecryptPEM for $ty {
            fn pem_hdr_tag() -> String {
                format!("----- BEGIN {} v1 -----", $tag)
            }
            fn pem_ftr_tag() -> String {
                format!("----- END {} v1 -----", $tag)
            }
            fn pem_sz() -> usize {
                Self::byte_sz()
                    + (Self::byte_sz() / PEM_CHUNK_SZ)
                    + <$ty>::pem_hdr_tag().len()
                    + 1
                    + <$ty>::pem_ftr_tag().len()
                    + 1
            }
            fn pem(&self) -> String {
                let pem_bytes = self.to_bytes();
                let mut out = format!("{}\n", <$ty>::pem_hdr_tag());
                for chunk in pem_bytes.chunks(PEM_CHUNK_SZ) {
                    writeln!(&mut out, "{}", hex::encode(chunk)).unwrap();
                }
                out.push_str(format!("{}\n", <$ty>::pem_ftr_tag()).as_str());
                out
            }
            fn loads(pem: &str) -> Result<Self, AloecryptError> {
                let stripped: String = pem.lines().map(|l| l.trim()).collect();
                if !stripped.starts_with(&<$ty>::pem_hdr_tag())
                    || !stripped.ends_with(&<$ty>::pem_ftr_tag())
                {
                    return Err(AloecryptError::InvalidPemTags);
                }
                let hex_body = &stripped
                    [<$ty>::pem_hdr_tag().len()..stripped.len() - <$ty>::pem_ftr_tag().len()];
                let bytes = hex::decode(hex_body).map_err(|_| AloecryptError::InvalidPemFormat)?;
                if bytes.len() != Self::byte_sz() {
                    return Err(AloecryptError::InvalidPemLength);
                }
                Ok(<$ty>::from_bytes(bytes))
            }
        }
    };
}

use super::builder::{PartyCHALLENGE, PartyCIPHER, PartyINTRO, PartyRESPONSE};
use super::message::*;

impl_msg_pem!(MsgHELLO, crate::consts::MSG_HELLO_PEM_TAG);
impl_msg_pem!(MsgSYN, crate::consts::MSG_SYN_PEM_TAG);
impl_msg_pem!(MsgACK, crate::consts::MSG_ACK_PEM_TAG);
impl_msg_pem!(MsgSYNACK, crate::consts::MSG_SYNACK_PEM_TAG);
impl_msg_pem!(MsgWELCOME, crate::consts::MSG_WELCOME_PEM_TAG);
impl_msg_pem!(MsgGOODBYE, crate::consts::MSG_GOODBYE_PEM_TAG);
impl_msg_pem!(MsgRETRY, crate::consts::MSG_RETRY_PEM_TAG);
impl_msg_pem!(MsgRESYN, crate::consts::MSG_RESYN_PEM_TAG);
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
