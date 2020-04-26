// Copyright 2019 Centrality Investments Limited

//!
//! Doughnut trait impls
//!

use crate::alloc::vec::Vec;
use crate::error::{ValidationError, VerifyError};
use crate::traits::{DoughnutApi, DoughnutVerify};

#[cfg(feature = "std")]
use crate::doughnut::Doughnut;

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
        Vec::default()
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
            self.signature().as_ref(),
            self.signature_version(),
            self.issuer().as_ref(),
            &self.payload(),
        )
    }
}

#[cfg(feature = "std")]
impl DoughnutVerify for ParityDoughnutV0 {
    fn verify(&self) -> Result<(), VerifyError> {
        verify_signature(
            &self.signature.as_ref(),
            self.signature_version(),
            &self.issuer().as_ref(),
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
    use bit_reverse::ParallelReverse;
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
        vec![
            196, 94, 16, 0, 75, 32, 0, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0,
            0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108, 115, 101, 0, 0,
            0, 128, 0, 0, 0,
        ]
    }

    macro_rules! vec_bits_swap {
        ($vector:expr) => {
            $vector.iter().map(|&b: &u8| b.swap_bits()).collect();
        };
    }

    #[test]
    fn it_verifies_an_sr25519_signed_doughnut_v0() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);
        let header: Vec<u8> = vec![0, 0, 192];
        let issuer = vec_bits_swap!(keypair.public.to_bytes().to_vec());
        let holder = vec_bits_swap!(vec![0x15; 32]);

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();

        let signature = keypair.sign(context.bytes(&payload));
        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut v0");
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn sr25519_signed_doughnut_v0_has_invalid_signature() {
        let keypair = generate_sr25519_keypair();
        let keypair_invalid = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);
        let header: Vec<u8> = vec![0, 0, 192];
        let issuer = vec_bits_swap!(keypair.public.to_bytes().to_vec());
        let holder = vec_bits_swap!(vec![0x15; 32]);

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();

        let signature = keypair_invalid.sign(context.bytes(&payload));
        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();
        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut v0");

        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }

    #[test]
    fn it_verifies_an_ed25519_signed_doughnut_v0() {
        let keypair = generate_ed25519_keypair();
        let header: Vec<u8> = vec![128, 0, 192];
        let issuer = vec_bits_swap!(keypair.public.to_bytes().to_vec());
        let holder = vec_bits_swap!(vec![0x15; 32]);
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let signature = keypair.sign(&payload);
        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();
        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut v0");
        assert_eq!(doughnut.verify(), Ok(()));
    }

    #[test]
    fn ed25519_signed_doughnut_v0_has_invalid_signature() {
        let keypair = generate_ed25519_keypair();
        let header: Vec<u8> = vec![128, 0, 192];
        let issuer = vec_bits_swap!(keypair.public.to_bytes().to_vec());
        let holder = vec_bits_swap!(vec![0x15; 32]);
        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();
        let signature = keypair.sign(&payload);
        let mut encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();
        let index = encoded.len() - 1;
        encoded[index] = 0x00;
        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut v0");
        assert_eq!(doughnut.verify(), Err(VerifyError::Invalid));
    }

    #[test]
    fn it_verifies_an_sr25519_signed_doughnut() {
        let keypair = generate_sr25519_keypair();
        let context = signing_context(CONTEXT_ID);
        let header: Vec<u8> = vec![0, 0, 192];
        let issuer = vec_bits_swap!(keypair.public.to_bytes().to_vec());
        let holder = vec_bits_swap!(vec![0x15; 32]);

        let payload: Vec<u8> = [header, issuer, holder, test_domain_data()].concat();

        let signature = keypair.sign(context.bytes(&payload));
        let encoded: Vec<u8> = [payload, signature.to_bytes().to_vec()].concat();

        let doughnut: ParityDoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut v0");
        assert_eq!(doughnut.verify(), Ok(()));
    }
}
