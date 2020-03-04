// Copyright 2019 Centrality Investments Limited

use crate::error::VerifyError;
use core::convert::TryFrom;
use ed25519_dalek::{PublicKey as Ed25519Pub, Signature as Ed25519Sig};
use schnorrkel::{signing_context, PublicKey as Sr25519Pub, Signature as Sr25519Sig};

/// Doughnut signature version
enum SignatureVersion {
    Sr25519 = 0,
    Ed25519 = 1,
}

impl TryFrom<u8> for SignatureVersion {
    type Error = VerifyError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Sr25519),
            1 => Ok(Self::Ed25519),
            _ => Err(VerifyError::UnsupportedVersion),
        }
    }
}

/// Verify the signature for a `DoughnutApi` impl type
#[allow(clippy::module_name_repetitions)]
pub fn verify_signature(
    signature_bytes: &[u8],
    version_byte: u8,
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let version = SignatureVersion::try_from(version_byte).map_err(|_| false);
    match version.unwrap() {
        SignatureVersion::Ed25519 => verify_ed25519_signature(signature_bytes, signer, payload),
        SignatureVersion::Sr25519 => verify_sr25519_signature(signature_bytes, signer, payload),
    }
}

/// Verify an ed25519 signature
fn verify_ed25519_signature(
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let signature =
        Ed25519Sig::from_bytes(signature_bytes).map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key = Ed25519Pub::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    public_key
        .verify(payload, &signature)
        .map_err(|_| VerifyError::Invalid)
}

/// Verify an sr25519 signature
fn verify_sr25519_signature(
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let signature =
        Sr25519Sig::from_bytes(signature_bytes).map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key = Sr25519Pub::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    public_key
        .verify(signing_context(b"substrate").bytes(payload), &signature)
        .map_err(|_| VerifyError::Invalid)
}
