// Copyright 2019-2020 Centrality Investments Limited

use crate::error::VerifyError;
use core::convert::TryFrom;
use ed25519_dalek::{PublicKey as Ed25519Pub, Signature as Ed25519Sig};
use schnorrkel::{signing_context, PublicKey as Sr25519Pub, Signature as Sr25519Sig};

pub const CONTEXT_ID: &[u8] = b"substrate";

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
    let version = SignatureVersion::try_from(version_byte)?;
    match version {
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
        .verify(signing_context(CONTEXT_ID).bytes(payload), &signature)
        .map_err(|_| VerifyError::Invalid)
}

#[cfg(test)]
mod test {
    use super::*;
    // The ed25519 and schnorrkel libs use different implementations of `OsRng`
    // two different libraries are used: `rand` and `rand_core` as a workaround
    use ed25519_dalek::Keypair as edKeypair;
    use rand::prelude::*;
    use rand_core::OsRng;
    use schnorrkel::Keypair as srKeypair;

    fn generate_ed25519_keypair() -> edKeypair {
        let mut csprng = OsRng {};
        edKeypair::generate(&mut csprng)
    }

    fn generate_sr25519_keypair() -> srKeypair {
        let mut csprng: ThreadRng = thread_rng();
        srKeypair::generate_with(&mut csprng)
    }

    #[test]
    fn test_ed25519_signature_verifies() {
        let keypair = generate_ed25519_keypair();
        let payload = "To a deep sea diver who is swimming with a raincoat";
        verify_ed25519_signature(
            &keypair.sign(&payload.as_bytes()).to_bytes(),
            &keypair.public.to_bytes(),
            payload.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_ed25519_signature_does_not_verify() {
        let keypair = generate_ed25519_keypair();
        let payload = "To a deep sea diver who is swimming with a raincoat";
        let signed_payload = "To a deep sea diver who is swimming without a raincoat";
        assert_eq!(
            verify_ed25519_signature(
                &keypair.sign(&signed_payload.as_bytes()).to_bytes(),
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn test_sr25519_signature_verifies() {
        let keypair = generate_sr25519_keypair();
        let payload = "Where your crystal mind and magenta feelings";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(payload.as_bytes()));
        verify_sr25519_signature(
            &signature.to_bytes(),
            &keypair.public.to_bytes(),
            payload.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_sr25519_signature_does_not_verify_bad_signature() {
        let keypair = generate_sr25519_keypair();
        let payload = "Where your crystal mind and magenta feelings";
        let signed_payload = "Where your crystal mind and purple feelings";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(signed_payload.as_bytes()));
        assert_eq!(
            verify_sr25519_signature(
                &signature.to_bytes(),
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn test_sr25519_signature_does_not_verify_bad_domain() {
        let keypair = generate_sr25519_keypair();
        let payload = "Where your crystal mind and magenta feelings";
        let context = signing_context(b"hoaniland");
        let signature = keypair.sign(context.bytes(payload.as_bytes()));
        assert_eq!(
            verify_sr25519_signature(
                &signature.to_bytes(),
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn test_verifies_ed25519_version() {
        let keypair = generate_ed25519_keypair();
        let payload = "When I get to you";
        verify_signature(
            &keypair.sign(&payload.as_bytes()).to_bytes(),
            1,
            &keypair.public.to_bytes(),
            payload.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_verifies_sr25519_version() {
        let keypair = generate_sr25519_keypair();
        let payload = "When I get to you";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(payload.as_bytes()));

        verify_signature(
            &signature.to_bytes(),
            0,
            &keypair.public.to_bytes(),
            payload.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_error_on_wrong_version() {
        let keypair = generate_sr25519_keypair();
        let payload = "When I get to you";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(payload.as_bytes()));

        assert_eq!(
            verify_signature(
                &signature.to_bytes(),
                1,
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::BadSignatureFormat)
        );
    }

    #[test]
    fn test_error_on_bad_version() {
        let keypair = generate_sr25519_keypair();
        let payload = "When I get to you";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(payload.as_bytes()));

        assert_eq!(
            verify_signature(
                &signature.to_bytes(),
                0x1f,
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::UnsupportedVersion)
        );
    }
}
