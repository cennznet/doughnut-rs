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
            0 => Ok(SignatureVersion::Sr25519),
            1 => Ok(SignatureVersion::Ed25519),
            _ => Err(VerifyError::UnsupportedVersion),
        }
    }
}

/// Verify the signature for a DoughnutApi impl type
pub fn verify_signature(
    signature: &[u8],
    version: u8,
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let _version = SignatureVersion::try_from(version).map_err(|_| false);
    match _version.unwrap() {
        SignatureVersion::Sr25519 => verify_sr25519_signature(signature, signer, payload),
        SignatureVersion::Ed25519 => verify_ed25519_signature(signature, signer, payload),
    }
}

/// Verify an ed25519 signature
fn verify_ed25519_signature(
    signature: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let _signature =
        Ed25519Sig::from_bytes(signature).map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key = Ed25519Pub::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    public_key
        .verify(payload, &_signature)
        .map_err(|_| VerifyError::Invalid)
}

/// Verify an sr25519 signature
fn verify_sr25519_signature(
    signature: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let _signature =
        Sr25519Sig::from_bytes(signature).map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key = Sr25519Pub::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    // newer versions of `sr25519` return `Result` not `bool`
    if public_key.verify(signing_context(b"substrate").bytes(payload), &_signature) {
        Ok(())
    } else {
        Err(VerifyError::Invalid)
    }
}
