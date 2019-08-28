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
//! Doughnut traits
//!
use crate::alloc::vec::Vec;
use crate::error::ValidationError;
use core::convert::TryInto;
mod impls;

/// An API trait to expose doughnut impl data
pub trait DoughnutApi {
    /// The holder and issuer public key type
    type PublicKey: PartialEq + AsRef<[u8]>;
    /// The expiry timestamp type
    type Timestamp: PartialOrd + Into<u32>;
    /// The signature type
    type Signature;
    /// Return the doughnut holder
    fn holder(&self) -> Self::PublicKey;
    /// Return the doughnut issuer
    fn issuer(&self) -> Self::PublicKey;
    /// Return the doughnut expiry timestamp
    fn expiry(&self) -> Self::Timestamp;
    /// Return the doughnut 'not before' timestamp
    fn not_before(&self) -> Self::Timestamp;
    /// Return the doughnut payload bytes
    fn payload(&self) -> Vec<u8>;
    /// Return the doughnut signature
    fn signature(&self) -> Self::Signature;
    /// Return the doughnut signature version
    fn signature_version(&self) -> u8;
    /// Return the payload for domain, if it exists in the doughnut
    fn get_domain(&self, domain: &str) -> Option<&[u8]>;
    /// Validate the doughnut is usable by a public key (`who`) at the current timestamp (`not_before` <= `now` <= `expiry`)
    fn validate<Q, R>(&self, who: Q, now: R) -> Result<(), ValidationError>
    where
        Q: AsRef<[u8]>,
        R: TryInto<u32>,
    {
        if who.as_ref() != self.holder().as_ref() {
            return Err(ValidationError::HolderIdentityMismatched);
        }
        let now_ = now.try_into().map_err(|_| ValidationError::Conversion)?;
        if now_ < self.not_before().into() {
            return Err(ValidationError::Premature);
        }
        if now_ >= self.expiry().into() {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

/// Provide doughnut signature checks
pub trait DoughnutVerify {
    /// Verify the doughnut signature, return whether it is valid or not
    fn verify(&self) -> bool;
}
