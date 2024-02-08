// Copyright 2022-2023 Futureverse Corporation Limited

//!
//! Doughnut traits
//!

use crate::error::CodecError;
use crate::{
    alloc::vec::Vec,
    error::{SigningError, ValidationError, VerifyError},
};
use codec::{Error, Input};
use core::convert::TryInto;

/// An enum for doughnut fee mode
pub enum FeeMode {
    ISSUER = 0,
    HOLDER = 1,
}

/// An enum for doughnut payload version
pub enum PayloadVersion {
    V0 = 0,
    V1 = 1,
}

impl TryFrom<u16> for PayloadVersion {
    type Error = CodecError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            _ => Err(CodecError::UnsupportedVersion),
        }
    }
}

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
    /// Return the doughnut fee mode
    fn fee_mode(&self) -> u8;
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
    /// Return the doughnut fee payer
    fn fee_payer(&self) -> Self::PublicKey {
        match self.fee_mode() {
            0 => self.issuer(),
            1 => self.holder(),
            _ => self.issuer(), // any other value default to the issuer
        }
    }
}

/// Provide doughnut signing
pub trait Signing {
    /// sign using Ed25519 method
    fn sign_ed25519(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 64], SigningError>;

    /// sign using Sr25519 method
    fn sign_sr25519(&mut self, secret_key: &[u8; 64]) -> Result<[u8; 64], SigningError>;

    /// sign using ECDSA method
    fn sign_ecdsa(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 65], SigningError>;

    /// sign using EIP191 method
    fn sign_eip191(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 65], SigningError>;
}

/// Provide doughnut signature checks
pub trait DoughnutVerify {
    /// Verify the doughnut signature, return whether it is valid or not
    fn verify(&self) -> Result<(), VerifyError>;
}

// Dummy implementation for unit type
impl DoughnutApi for () {
    type PublicKey = [u8; 32];
    type Timestamp = u32;
    type Signature = ();

    fn holder(&self) -> Self::PublicKey {
        Default::default()
    }
    fn issuer(&self) -> Self::PublicKey {
        Default::default()
    }
    fn fee_mode(&self) -> u8 {
        0
    }
    fn expiry(&self) -> Self::Timestamp {
        0
    }
    fn not_before(&self) -> Self::Timestamp {
        0
    }
    fn payload(&self) -> Vec<u8> {
        Vec::<u8>::default()
    }
    fn signature(&self) -> Self::Signature {
        Default::default()
    }
    fn signature_version(&self) -> u8 {
        255
    }
    fn get_domain(&self, _domain: &str) -> Option<&[u8]> {
        None
    }
    fn validate<Q, R>(&self, _who: Q, _now: R) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl DoughnutVerify for () {
    fn verify(&self) -> Result<(), VerifyError> {
        Ok(())
    }
}

/// Additional decoder trait that allows to decode with or without payload version info
pub trait DecodeInner: Sized {
    /// Decodes the doughnut payload with or without payload version info
    fn decode_inner<I: Input>(input: &mut I, with_version_info: bool) -> Result<Self, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        doughnut::DoughnutV0,
        signature::{SignatureVersion, CONTEXT_ID},
        traits::{DoughnutVerify, Signing},
    };
    use codec::Decode;
    use primitive_types::H512;
    // The ed25519 and schnorrkel libs use different implementations of `OsRng`
    // two different libraries are used: `rand` and `rand_core` as a workaround
    use ed25519_dalek::{Keypair as Ed25519Keypair, Signer};
    use rand::prelude::*;
    use rand_core::OsRng;
    use schnorrkel::{signing_context, Keypair as srKeypair};

    fn generate_ed25519_keypair() -> Ed25519Keypair {
        let mut csprng = OsRng {};
        Ed25519Keypair::generate(&mut csprng)
    }

    fn generate_sr25519_keypair() -> srKeypair {
        let mut csprng: ThreadRng = thread_rng();
        srKeypair::generate_with(&mut csprng)
    }

    fn test_domain_data() -> Vec<u8> {
        let domain_id_1 = vec![
            115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0,
        ];
        let domain_id_2 = vec![
            115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108, 115, 101, 0, 0, 0,
        ];
        [
            vec![196, 94, 16, 0, 75, 32, 0, 0], // expiry and not before
            domain_id_1,
            vec![1, 0], // domain length
            domain_id_2,
            vec![1, 0], // domain length
            vec![0, 0], // domain data
        ]
        .concat()
    }

    #[test]
    fn can_sign_and_verify_sr25519_signature() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);

        // Signature version = 0
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let invalid_payload_stub = [0_u8; 64];
        let invalid_signature_bytes = keypair
            .sign(context.bytes(&invalid_payload_stub))
            .to_bytes()
            .to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");
        let secret_key = keypair.secret.to_ed25519_bytes();

        // Signnature cannot be verified before signing
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));

        // Sign a Doughnut and return newly signed signature
        let signature: [u8; 64] = doughnut.sign_sr25519(&secret_key).expect("it signed ok");

        // Assume signature is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature, H512::from_slice(signature.as_slice()));

        // Assume signature_version is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature_version, 0);

        // Assume signed signature is verified ok
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn can_sign_and_verify_ed25519_signature() {
        let keypair = generate_ed25519_keypair();

        // Signature version = 1 (b3)
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 8, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let invalid_payload_stub = [0_u8; 64];
        let invalid_signature_bytes = keypair.sign(&invalid_payload_stub).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");
        let secret_key = keypair.secret.as_bytes();

        // Signnature cannot be verified before signing
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));

        // Sign a Doughnut and return newly signed signature
        let signature: [u8; 64] = doughnut.sign_ed25519(secret_key).expect("it signed ok");

        // Assume signature is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature, H512::from_slice(signature.as_slice()));

        // Assume signature_version is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature_version, 1);

        // Assume signed signature is verified ok
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn ed25519_signature_verifies() {
        let keypair = generate_ed25519_keypair();
        let issuer = keypair.public.to_bytes();
        let holder = [0x15; 32];
        let domains = vec![("test".to_string(), vec![0u8])];
        let mut doughnut = DoughnutV0 {
            issuer,
            holder,
            domains,
            ..Default::default()
        };
        doughnut.sign_ed25519(&keypair.secret.to_bytes()).unwrap();
        assert_eq!(
            doughnut.signature_version(),
            SignatureVersion::Ed25519 as u8
        );
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn sr25519_signature_verifies() {
        let keypair = generate_sr25519_keypair();
        let issuer = keypair.public.to_bytes();
        let holder = [0x15; 32];
        let domains = vec![("test".to_string(), vec![0u8])];
        let mut doughnut = DoughnutV0 {
            issuer,
            holder,
            domains,
            ..Default::default()
        };
        doughnut
            .sign_sr25519(&keypair.secret.to_ed25519_bytes())
            .unwrap();
        assert_eq!(
            doughnut.signature_version(),
            SignatureVersion::Sr25519 as u8
        );
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn sr25519_signed_doughnut_v0_has_invalid_signature() {
        let keypair = generate_sr25519_keypair();
        let keypair_invalid = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);

        // Signature version = 0
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let invalid_signature = keypair_invalid.sign(context.bytes(&payload));

        let encoded: Vec<u8> = [payload, invalid_signature.to_bytes().to_vec()].concat();

        let doughnut = DoughnutV0::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }

    #[test]
    fn ed25519_signed_doughnut_v0_has_invalid_signature() {
        let keypair = generate_ed25519_keypair();

        // Signature version = 1 (b3)
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 8, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let signature = keypair.sign(&payload);

        let mut encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();
        let index = encoded.len() - 1;

        // Make the signature invalid
        encoded[index] = match encoded[index] {
            0 => 1,
            _ => 0,
        };

        let doughnut = DoughnutV0::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }
}
