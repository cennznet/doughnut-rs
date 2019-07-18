// Copyright 2019 Centrality Investments Limited
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
//!
//! Doughnut trait impls
//!
use super::DoughnutApi;
use crate::alloc::vec::Vec;
use crate::error::ValidationError;

// Dummy implementation for unit type
impl DoughnutApi for () {
    type PublicKey = ();
    type Timestamp = ();
    type Signature = ();
    fn holder(&self) -> Self::PublicKey {
        ()
    }
    fn issuer(&self) -> Self::PublicKey {
        ()
    }
    fn expiry(&self) -> Self::PublicKey {
        ()
    }
    fn not_before(&self) -> Self::Timestamp {
        ()
    }
    fn payload(&self) -> Vec<u8> {
        Default::default()
    }
    fn signature(&self) -> Self::Signature {
        ()
    }
    fn signature_version(&self) -> u8 {
        255
    }
    fn get_domain(&self, _domain: &str) -> Option<&[u8]> {
        None
    }
    fn validate(
        &self,
        _who: &Self::PublicKey,
        _now: Self::Timestamp,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}
