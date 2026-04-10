// src/option_big_array.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_big_array::BigArray;

pub fn serialize<S, const N: usize>(val: &Option<[u8; N]>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        Some(arr) => s.serialize_some(&serde_bytes::Bytes::new(arr)),
        None => s.serialize_none(),
    }
}

pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(buf) => {
            let arr: [u8; N] = buf.into_vec().try_into().map_err(|_| {
                serde::de::Error::custom(format!("expected byte array of length {}", N))
            })?;
            Ok(Some(arr))
        }
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
