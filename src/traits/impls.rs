// Copyright 2019-2020 Centrality Investments Limited

//! Doughnut trait impls
use crate::{
    alloc::vec::Vec,
    error::{ValidationError, VerifyError},
    traits::{DoughnutApi, DoughnutVerify},
};

#[cfg(feature = "std")]
use crate::v0::{parity::DoughnutV0 as ParityDoughnutV0, DoughnutV0};

#[cfg(feature = "std")]
use crate::signature::verify_signature;

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
    fn signature(&self) -> Self::Signature {}
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

#[cfg(feature = "std")]
impl<'a> DoughnutVerify for DoughnutV0<'a> {
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
impl DoughnutVerify for ParityDoughnutV0 {
    fn verify(&self) -> Result<(), VerifyError> {
        verify_signature(
            &self.signature(),
            self.signature_version(),
            &self.issuer(),
            &self.payload(),
        )
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
    use ed25519_dalek::Keypair as edKeypair;
    use rand::prelude::*;
    use rand_core::OsRng;
    use schnorrkel::{signing_context, Keypair as srKeypair};

    fn generate_ed25519_keypair() -> edKeypair {
        let mut csprng = OsRng {};
        edKeypair::generate(&mut csprng)
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
    fn it_verifies_an_sr25519_signed_doughnut_v0() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);

        // Signature version = 0
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 0, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let signature = keypair.sign(context.bytes(&payload));

        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Ok(()));

        // enclosed doughnut
        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
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

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }

    #[test]
    fn it_verifies_an_ed25519_signed_doughnut_v0() {
        let keypair = generate_ed25519_keypair();

        // Signature version = 1 (b3)
        // has not before (b0) and 2 domains (b1..7)
        let header: Vec<u8> = vec![0, 8, 3];
        let issuer = keypair.public.to_bytes().to_vec();
        let holder = vec![0x15; 32];

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let signature = keypair.sign(&payload);

        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Ok(()));
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

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }
}
