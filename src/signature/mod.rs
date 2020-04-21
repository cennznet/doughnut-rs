// Copyright 2019 Centrality Investments Limited

use crate::error::{SignError, VerifyError};
use core::convert::TryFrom;
use ed25519_dalek::{
    Keypair as EdKeypair, PublicKey as Ed25519Pub, Signature as Ed25519Sig,
    KEYPAIR_LENGTH as ED_KEYPAIR_LENGTH, SECRET_KEY_LENGTH as ED_SECRET_KEY_LENGTH,
};
use schnorrkel::{
    signing_context, PublicKey as Sr25519Pub, SecretKey as Sr25519Sec,
    Signature as Sr25519Sig,
};

// TODO: should change context to `cennznet`
const SIGNING_CTX: &'static [u8] = b"substrate";

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

/// Sign a message
pub fn sign(
    public: &[u8],
    secret: &[u8],
    version_byte: u8,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    let version =
        SignatureVersion::try_from(version_byte).map_err(|_| SignError::UnsupportedVersion);
    match version.unwrap() {
        SignatureVersion::Sr25519 => sign_sr25519(public, secret, message),
        SignatureVersion::Ed25519 => sign_ed25519(public, secret, message),
    }
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

/// Sign a massage with sr25519 keypair
fn sign_sr25519(public: &[u8], secret: &[u8], message: &[u8]) -> Result<Vec<u8>, SignError> {
    // TODO: verify public key
    let signature = Sr25519Sec::from_ed25519_bytes(secret)
        .unwrap()
        .sign_simple(
            SIGNING_CTX,
            message,
            &Sr25519Pub::from_bytes(public).unwrap(),
        )
        .to_bytes()
        .to_vec();

    Ok(signature)
}

/// Sign a massage with ed25519 keypair
fn sign_ed25519(public: &[u8], secret: &[u8], message: &[u8]) -> Result<Vec<u8>, SignError> {
    let public_key = &secret[ED_SECRET_KEY_LENGTH..ED_KEYPAIR_LENGTH];
    if (from_slice(public) != from_slice(public_key)) {
        return Err(SignError::InvalidKeypair);
    }

    let keypair = EdKeypair::from_bytes(secret).map_err(|_| SignError::InvalidKeypair)?;
    let signature = keypair.sign(message).to_bytes().to_vec();

    Ok(signature)
}

/// Verify the signature for a `DoughnutApi` impl type
#[allow(clippy::module_name_repetitions)]
pub fn verify_signature(
    signature_bytes: &[u8],
    version_byte: u8,
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let version =
        SignatureVersion::try_from(version_byte).map_err(|_| VerifyError::UnsupportedVersion);
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
        .verify(signing_context(SIGNING_CTX).bytes(payload), &signature)
        .map_err(|_| VerifyError::Invalid)
}
