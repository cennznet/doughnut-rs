// Copyright 2019-2020 Centrality Investments Limited

//! Doughnut trait impls
use crate::{
    alloc::vec::Vec,
    error::{ValidationError, VerifyError},
    traits::{DoughnutApi, DoughnutVerify},
};

#[cfg(feature = "std")]
use ed25519_dalek::Signer;

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

#[cfg(feature = "crypto")]
pub mod crypto {
    //! Crypto.verification and signing impls for Doughnut types
    use crate::{
        alloc::vec::Vec,
        doughnut::Doughnut,
        error::{SigningError, VerifyError},
        signature::{sign_ed25519, sign_sr25519, verify_signature, SignatureVersion},
        traits::{DoughnutApi, DoughnutVerify, Signing},
        v0::DoughnutV0, v1::DoughnutV1,
    };
    use primitive_types::H512;
    #[cfg(feature = "std")]
    use crate::signature::sign_ecdsa;
    #[cfg(feature = "std")]
    use std::convert::TryInto;

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

    impl DoughnutVerify for DoughnutV1 {
        fn verify(&self) -> Result<(), VerifyError> {
            verify_signature(
                &self.signature(),
                self.signature_version(),
                &self.issuer(),
                &self.payload(),
            )
        }
    }

    #[allow(unreachable_patterns)]
    impl DoughnutVerify for Doughnut {
        fn verify(&self) -> Result<(), VerifyError> {
            match self {
                Self::V0(v0) => v0.verify(),
                Self::V1(v1) => v1.verify(),
                _ => Err(VerifyError::UnsupportedVersion),
            }
        }
    }

    impl Signing for DoughnutV0 {
        fn sign_ed25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.signature_version = SignatureVersion::Ed25519 as u8;
            sign_ed25519(&self.issuer(), secret_key, &self.payload()).map(|signature| {
                self.signature = H512::from_slice(&signature);
                signature
            })
        }

        fn sign_sr25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.signature_version = SignatureVersion::Sr25519 as u8;
            sign_sr25519(&self.issuer(), secret_key, &self.payload()).map(|signature| {
                self.signature = H512::from_slice(&signature);
                signature
            })
        }

        #[cfg(feature = "std")]
        fn sign_ecdsa(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            Err(SigningError::NotSupported)
        }
    }

    impl Signing for DoughnutV1 {
        fn sign_ed25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            Err(SigningError::NotSupported)
        }

        fn sign_sr25519(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            Err(SigningError::NotSupported)
        }

        #[cfg(feature = "std")]
        fn sign_ecdsa(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, SigningError> {
            self.signature_version = SignatureVersion::ECDSA as u8;
            sign_ecdsa(secret_key, &self.payload()).map(|signature| {
                self.signature = signature.clone().try_into().expect("signature must be 65 byte long");
                signature
            })
        }
    }
}

impl DoughnutVerify for () {
    fn verify(&self) -> Result<(), VerifyError> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        error::SigningError,
        signature::{SignatureVersion, CONTEXT_ID},
        traits::{DoughnutVerify, Signing},
        v0::DoughnutV0,
    };
    use codec::Decode;
    use primitive_types::H512;
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
        let signature: Vec<u8> = doughnut.sign_sr25519(&secret_key).expect("it signed ok");

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
        let signature: Vec<u8> = doughnut.sign_ed25519(secret_key).expect("it signed ok");

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
    fn throw_error_when_sign_sr25519_signature_with_invalid_secret_key() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);

        // Signature version = 0
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let valid_signature_bytes = keypair.sign(context.bytes(&payload)).to_bytes().to_vec();
        let encoded_with_valid_signature: Vec<u8> = [payload, valid_signature_bytes].concat();
        let mut doughnut: DoughnutV0 =
            Decode::decode(&mut &encoded_with_valid_signature[..]).expect("It is a valid doughnut");

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
        let valid_signature_bytes = keypair.sign(&payload).to_bytes().to_vec();
        let encoded_with_invalid_signature: Vec<u8> = [payload, valid_signature_bytes].concat();
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
