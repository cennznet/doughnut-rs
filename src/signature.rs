// Copyright 2022-2023 Futureverse Corporation Limited

use crate::alloc::vec::Vec;
use crate::error::{SigningError, VerifyError};
use blake2::{digest, Digest};
use core::convert::{TryFrom, TryInto};
use digest::consts::U32;
use ed25519_dalek::{
    Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, Signature as Ed25519Signature,
    Signer, Verifier,
};
use schnorrkel::{
    signing_context, PublicKey as Sr25519PublicKey, SecretKey as Sr25519SecretKey,
    Signature as Sr25519Signature,
};

pub const CONTEXT_ID: &[u8] = b"doughnut";

/// Doughnut signature version
#[allow(clippy::module_name_repetitions)]
pub enum SignatureVersion {
    Sr25519 = 0,
    Ed25519 = 1,
    ECDSA = 2,
}

impl TryFrom<u8> for SignatureVersion {
    type Error = VerifyError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Sr25519),
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::ECDSA),
            _ => Err(VerifyError::UnsupportedVersion),
        }
    }
}

/// Sign an ed25519 signature
pub fn sign_ed25519(
    public_key: &[u8; 32],
    secret_key: &[u8; 32],
    payload: &[u8],
) -> Result<[u8; 64], SigningError> {
    let pair_bytes: Vec<u8> = [secret_key.to_vec(), public_key.to_vec()].concat();
    let keypair =
        Ed25519Keypair::from_bytes(&pair_bytes).map_err(|_| SigningError::InvalidEd25519Key)?;

    Ok(keypair.sign(payload).to_bytes())
}

/// Sign an sr25519 signature
pub fn sign_sr25519(
    public_key: &[u8],
    secret_key: &[u8; 64],
    payload: &[u8],
) -> Result<[u8; 64], SigningError> {
    let secret_key = Sr25519SecretKey::from_ed25519_bytes(&secret_key[..])
        .map_err(|_| SigningError::InvalidSr25519SecretKey)?;
    let public_key = Sr25519PublicKey::from_bytes(public_key)
        .map_err(|_| SigningError::InvalidSr25519PublicKey)?;

    Ok(secret_key
        .sign_simple(CONTEXT_ID, payload, &public_key)
        .to_bytes())
}

/// Sign an ecdsa signature
pub fn sign_ecdsa(secret_key: &[u8; 32], payload: &[u8]) -> Result<[u8; 64], SigningError> {
    let payload_hashed = blake2_256(payload);
    let secret_key = libsecp256k1::SecretKey::parse_slice(secret_key)
        .map_err(|_| SigningError::InvalidECDSASecretKey)?;
    let message = libsecp256k1::Message::parse_slice(&payload_hashed)
        .map_err(|_| SigningError::InvalidPayload)?;
    let (signature, _) = libsecp256k1::sign(&message, &secret_key);
    Ok(signature.serialize())
}

/// Verify the signature for a `DoughnutApi` impl type
#[allow(clippy::module_name_repetitions)]
pub fn verify_signature(
    signature_version: u8,
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let version = SignatureVersion::try_from(signature_version)?;
    match version {
        SignatureVersion::Ed25519 => verify_ed25519_signature(signature_bytes, signer, payload),
        SignatureVersion::Sr25519 => verify_sr25519_signature(signature_bytes, signer, payload),
        SignatureVersion::ECDSA => verify_ecdsa_signature(signature_bytes, signer, payload),
    }
}

/// Verify an ed25519 signature
pub fn verify_ed25519_signature(
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let signature = Ed25519Signature::from_bytes(signature_bytes)
        .map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key =
        Ed25519PublicKey::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    public_key
        .verify(payload, &signature)
        .map_err(|_| VerifyError::Invalid)
}

/// Verify an sr25519 signature
pub fn verify_sr25519_signature(
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let signature = Sr25519Signature::from_bytes(signature_bytes)
        .map_err(|_| VerifyError::BadSignatureFormat)?;
    let public_key =
        Sr25519PublicKey::from_bytes(signer).map_err(|_| VerifyError::BadPublicKeyFormat)?;
    public_key
        .verify(signing_context(CONTEXT_ID).bytes(payload), &signature)
        .map_err(|_| VerifyError::Invalid)
}

/// Verify an ecdsa signature
pub fn verify_ecdsa_signature(
    signature_bytes: &[u8],
    signer: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    let payload_hashed = blake2_256(payload);
    let public_key: [u8; 33] = signer
        .try_into()
        .map_err(|_| VerifyError::BadPublicKeyFormat)?;

    let message = libsecp256k1::Message::parse(&payload_hashed);
    let signature = libsecp256k1::Signature::parse_standard_slice(&signature_bytes[..64])
        .map_err(|_| VerifyError::BadSignatureFormat)?;
    let pub_key = libsecp256k1::PublicKey::parse_compressed(&public_key)
        .map_err(|_| VerifyError::BadPublicKeyFormat)?;

    match libsecp256k1::verify(&message, &signature, &pub_key) {
        true => Ok(()),
        false => Err(VerifyError::Invalid),
    }
}

fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    type Blake2b256 = blake2::Blake2b<U32>;
    hash.copy_from_slice(Blake2b256::digest(data).as_slice());
    hash
}

#[cfg(test)]
mod test {
    use super::*;
    // The ed25519 and schnorrkel libs use different implementations of `OsRng`
    // two different libraries are used: `rand` and `rand_core` as a workaround
    use ed25519_dalek::{Keypair as Ed25519Keypair, SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH};
    use libsecp256k1::SecretKey as ECDSASecretKey;
    use rand::prelude::*;
    use rand_core::OsRng;
    use schnorrkel::{Keypair as Sr25519Keypair, SIGNATURE_LENGTH as SR25519_SIGNATURE_LENGTH};
    use sp_core::{ecdsa::Pair as ECDSAKeyPair, Pair};

    fn generate_ed25519_keypair() -> Ed25519Keypair {
        let mut csprng = OsRng {};
        Ed25519Keypair::generate(&mut csprng)
    }

    fn generate_sr25519_keypair() -> Sr25519Keypair {
        let mut csprng: ThreadRng = thread_rng();
        Sr25519Keypair::generate_with(&mut csprng)
    }

    fn generate_ecdsa_keypair() -> (ECDSAKeyPair, ECDSASecretKey) {
        let (pair, seed) = ECDSAKeyPair::generate();
        (
            pair,
            ECDSASecretKey::parse(&seed.into()).expect("can not error here"),
        )
    }

    #[test]
    fn can_sign_ed25519() {
        let keypair = generate_ed25519_keypair();
        let public_key = keypair.public.to_bytes();
        let secret_key = keypair.secret.as_bytes();
        let payload = "this is a payload".as_bytes();
        let signature = sign_ed25519(&public_key, secret_key, payload).unwrap();

        verify_ed25519_signature(&signature, &public_key, payload)
            .expect("Signed signature can be verified");

        assert!(signature.len() == ED25519_SIGNATURE_LENGTH);
    }

    #[test]
    fn can_sign_sr25519() {
        let keypair = generate_sr25519_keypair();
        let public_key = keypair.public.to_bytes();
        let secret_key = keypair.secret.to_ed25519_bytes();
        let payload = "this is a payload".as_bytes();
        let signature = sign_sr25519(&public_key, &secret_key, payload).unwrap();

        verify_sr25519_signature(&signature, &public_key, payload)
            .expect("Signed signature can be verified");

        assert!(signature.len() == SR25519_SIGNATURE_LENGTH);
    }

    #[test]
    fn can_sign_ecdsa() {
        const ECDSA_SIGNATURE_LENGTH: usize = 64;

        let (_, secret_key) = generate_ecdsa_keypair();
        let payload = "this is a payload".as_bytes();
        let signature = sign_ecdsa(&secret_key.serialize(), payload).unwrap();

        assert_eq!(signature.len(), ECDSA_SIGNATURE_LENGTH);
    }

    #[test]
    fn test_ecdsa_signature_verifies() {
        let (keypair, secret_key) = generate_ecdsa_keypair();
        let public_key = keypair.public();
        let payload = "this is a payload".as_bytes();
        let signature = sign_ecdsa(&secret_key.serialize(), payload).unwrap();

        verify_ecdsa_signature(&signature, &public_key.as_ref(), payload)
            .expect("Signed signature can be verified");
    }

    #[test]
    fn test_ecdsa_signature_verification_failed() {
        let (keypair, secret_key) = generate_ecdsa_keypair();
        let public_key = keypair.public();
        let payload = "To a deep sea diver who is swimming with a raincoat".as_bytes();
        let signed_payload = "To a deep sea diver who is swimming without a raincoat".as_bytes();
        let signature = sign_ecdsa(&secret_key.serialize(), signed_payload).unwrap();

        assert_eq!(
            verify_ecdsa_signature(&signature, &public_key.as_ref(), payload,),
            Err(VerifyError::Invalid)
        );
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
            1,
            &keypair.sign(&payload.as_bytes()).to_bytes(),
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
            0,
            &signature.to_bytes(),
            &keypair.public.to_bytes(),
            payload.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_verifies_ecdsa_version() {
        let (keypair, secret_key) = generate_ecdsa_keypair();
        let public_key = keypair.public();
        let payload = "this is a payload".as_bytes();
        let signature = sign_ecdsa(&secret_key.serialize(), payload).unwrap();

        verify_signature(2, &signature, &public_key.as_ref(), payload)
            .expect("Signed signature can be verified");
    }

    #[test]
    fn test_error_on_wrong_version() {
        let keypair = generate_sr25519_keypair();
        let payload = "When I get to you";
        let context = signing_context(CONTEXT_ID);
        let signature = keypair.sign(context.bytes(payload.as_bytes()));

        assert_eq!(
            verify_signature(
                1,
                &signature.to_bytes(),
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
                0x1f,
                &signature.to_bytes(),
                &keypair.public.to_bytes(),
                payload.as_bytes()
            ),
            Err(VerifyError::UnsupportedVersion)
        );
    }
}
