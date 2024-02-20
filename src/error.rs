// Copyright 2023-2024 Futureverse Corporation Limited

#![allow(clippy::module_name_repetitions)]

/// Error type for codec failures
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum CodecError {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding,
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
#[derive(PartialEq, Debug)]
pub enum VerifyError {
    /// Unsupported signature version
    UnsupportedVersion,
    /// Signature format is invalid
    BadSignatureFormat,
    /// PublicKey format is invalid
    BadPublicKeyFormat,
    /// Message payload format is invalid
    BadPayloadFormat,
    /// The signature does not verify the payload from signer
    Invalid,
}

/// A signature signing error
#[derive(PartialEq, Debug)]
pub enum SigningError {
    /// Provided public/secret key is invalid ed25519 signing
    InvalidEd25519Key,
    /// Provided public key is invalid for sr25519 signing
    InvalidSr25519PublicKey,
    /// Provided secret key is invalid for sr25519 signing
    InvalidSr25519SecretKey,
    /// Provided secret key is invalid for ECDSA signing
    InvalidECDSASecretKey,
    /// Provided payload is invalid
    InvalidPayload,
    /// Not supported
    NotSupported,
}
