// Copyright 2019-2020 Centrality Investments Limited

//! Doughnut trait impls
use primitive_types::H512;

use crate::{
    alloc::vec::Vec,
    error::{SigningError, ValidationError, VerifyError},
    traits::{DoughnutApi, DoughnutVerify, Signing},
};

#[cfg(feature = "std")]
use crate::{
    doughnut::Doughnut,
    signature::{sign_ed25519, sign_sr25519, verify_signature},
    v0::DoughnutV0,
};

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

#[cfg(feature = "std")]
impl Signing for DoughnutV0 {
    fn sign_ed25519(&mut self, secret_key: &[u8]) -> Result<H512, SigningError> {
        sign_ed25519(&self.issuer(), secret_key, &self.payload())
            .map(|signed_signature| H512::from_slice(&signed_signature))
            .map(|signature| {
                self.signature = signature;
                self.signature_version = 1 as u8;
                signature
            })
    }

    fn sign_sr25519(&mut self, secret_key: &[u8]) -> Result<H512, SigningError> {
        sign_sr25519(&self.issuer(), secret_key, &self.payload())
            .map(|signed_signature| H512::from_slice(&signed_signature))
            .map(|signature| {
                self.signature = signature;
                self.signature_version = 0 as u8;
                signature
            })
    }
}

impl DoughnutVerify for () {
    fn verify(&self) -> Result<(), VerifyError> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl DoughnutVerify for DoughnutV0 {
    fn verify(&self) -> Result<(), VerifyError> {
        verify_signature(
            &self.signature(),
            self.signature_version(),
            &self.issuer(),
            &self.payload(),
        )
    }
}

#[cfg(feature = "std")]
#[allow(unreachable_patterns)]
impl DoughnutVerify for Doughnut {
    fn verify(&self) -> Result<(), VerifyError> {
        match self {
            Self::V0(v0) => v0.verify(),
            _ => Err(VerifyError::UnsupportedVersion),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signature::CONTEXT_ID;
    use crate::traits::DoughnutVerify;
    use codec::Decode;
    // The ed25519 and schnorrkel libs use different implementations of `OsRng`
    // two different libraries are used: `rand` and `rand_core` as a workaround
    use ed25519_dalek::Keypair as Ed25519Keypair;
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
        let invalid_signature_bytes = keypair.sign(context.bytes(&[0u8])).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");
        let secret_key = keypair.secret.to_ed25519_bytes();

        // Signnature cannot be verified before signing
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));

        // Sign a Doughnut and return newly signed signature
        let signature = doughnut.sign_sr25519(&secret_key).expect("it signed ok");

        // Assume signature is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature, signature);

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
        let invalid_signature_bytes = keypair.sign(&[0u8]).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");
        let secret_key = keypair.secret.as_bytes();

        // Signnature cannot be verified before signing
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));

        // Sign a Doughnut and return newly signed signature
        let signature = doughnut.sign_ed25519(secret_key).expect("it signed ok");

        // Assume signature is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature, signature);

        // Assume signature_version is assigned to a Doughnut after signing
        assert_eq!(doughnut.signature_version, 1);

        // Assume signed signature is verified ok
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn throw_error_when_sign_sr25519_signature_with_invalid_secret_key() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);

        // Signature version = 0
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let invalid_signature_bytes = keypair.sign(context.bytes(&[0u8])).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");

        let secret_key = "secret_key supposes to be keypair.secret.to_ed25519_bytes()".as_bytes();

        assert_eq!(
            doughnut.sign_sr25519(&secret_key),
            Err(SigningError::InvalidSr25519SecretKey)
        );
    }

    #[test]
    fn throw_error_when_sign_ed25519_signature_with_invalid_secret_key() {
        let keypair = generate_ed25519_keypair();

        // Signature version = 1
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let invalid_signature_bytes = keypair.sign(&[0u8]).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, invalid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 = Decode::decode(&mut &encoded_with_invalid_signature[..])
            .expect("It is a valid doughnut");

        let secret_key = "secret_key supposes to be keypair.secret.as_bytes()".as_bytes();

        assert_eq!(
            doughnut.sign_ed25519(&secret_key),
            Err(SigningError::InvalidEd25519Key)
        );
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
