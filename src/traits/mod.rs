// Copyright 2019-2020 Centrality Investments Limited

//!
//! Doughnut traits
//!

use crate::{
    alloc::vec::Vec,
    error::{SigningError, ValidationError, VerifyError},
};
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

/// Provide doughnut signing
pub trait Signing {
    /// sign using Ed25519 method
    fn sign_ed25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// sign using Sr25519 method
    fn sign_sr25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// sign using ecdsa
    fn sign_ecdsa(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError>;
}

/// Provide doughnut signature checks
pub trait DoughnutVerify {
    /// Verify the doughnut signature, return whether it is valid or not
    fn verify(&self) -> Result<(), VerifyError>;
}
