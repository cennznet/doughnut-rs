// Copyright 2019 Centrality Investments Limited

#![allow(clippy::module_name_repetitions)]

/// Error type for codec failures
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum CodecError<'a> {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding(&'a str),
}

/// Error type for validation failures
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ValidationError {
    /// Public key attempting to use a doughnut does not match the issued holder
    HolderIdentityMismatched,
    /// The doughnut has expired against the current timestamp
    Expired,
    /// Doughnut use precedes it's 'not before' timestamp, thus it has not matured yet.
    Premature,
    /// A type conversion failed during validation e.g overflow
    Conversion,
}

/// A signature verification error
#[cfg_attr(feature = "std", derive(PartialEq, Debug))]
pub enum VerifyError {
    /// Unsupported signature version
    UnsupportedVersion,
    /// Signature format is invalid
    BadSignatureFormat,
    /// PublicKey format is invalid
    BadPublicKeyFormat,
    /// The signature does not verify the payload from signer
    Invalid,
}

/// Error type for sign message
#[cfg_attr(feature = "std", derive(PartialEq, Debug))]
pub enum SignError {
    /// Unsupported signature version
    UnsupportedVersion,
    /// PublicKey not match
    PublicKeyNotMatch,
    /// Keypair is invalid
    InvalidKeypair,
}
