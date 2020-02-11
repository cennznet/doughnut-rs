// Copyright 2019 Centrality Investments Limited

//!
//! Doughnut traits
//!

use crate::alloc::vec::Vec;
use crate::error::{ValidationError, VerifyError};
use core::convert::TryInto;
mod impls;

/// A version agnostic API trait to expose a doughnut's underlying data.
/// It requires that associated types implement certain conversion traits in order
/// to provide a default validation implementation.
pub trait DoughnutApi {
    /// The holder and issuer public key type
    type PublicKey: PartialEq + AsRef<[u8]>;
    /// The expiry timestamp type
    type Timestamp: PartialOrd + TryInto<u32>;
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
    /// # Errors
    /// This function will error if the doughnut is invalid for use given `who` and the timestamp `now`
    /// It may also fail on type conversions if:
    /// - `who` cannot be coerced into the doughnut public key type
    /// - `now` cannot be coerced into the doughnut timestamp type
    fn validate<Q, R>(&self, who: Q, now: R) -> Result<(), ValidationError>
    where
        Q: AsRef<[u8]>,
        R: TryInto<u32>,
    {
        if who.as_ref() != self.holder().as_ref() {
            return Err(ValidationError::HolderIdentityMismatched);
        }
        let now_ = now.try_into().map_err(|_| ValidationError::Conversion)?;
        if now_
            < self
                .not_before()
                .try_into()
                .map_err(|_| ValidationError::Conversion)?
        {
            return Err(ValidationError::Premature);
        }
        if now_
            >= self
                .expiry()
                .try_into()
                .map_err(|_| ValidationError::Conversion)?
        {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

/// Provide doughnut signature checks
pub trait DoughnutVerify {
    /// Verify the doughnut signature, return whether it is valid or not
    ///
    /// # Errors
    /// This function may fail for any reason described by `VerifyError` variants
    /// Primarily, the doughnut signature is invalid
    fn verify(&self) -> Result<(), VerifyError>;
}
