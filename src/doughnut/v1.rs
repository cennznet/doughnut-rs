// Copyright 2022-2023 Futureverse Corporation Limited

//!
//! Doughnut V1 codec
//! This version is for interoperability within the substrate extrinsic environment.
//! It uses the `codec` crate to consume a contiguous stream of bytes, without any look-ahead.
//! It however, does not use the SCALE codec.

#![allow(clippy::cast_possible_truncation)]

use crate::signature::SignatureVersion;
use crate::traits::{DecodeInner, DoughnutApi, PayloadVersion};
use crate::{
    alloc::{
        string::{String, ToString},
        vec::Vec,
    },
    doughnut::{SIGNATURE_MASK, SIGNATURE_OFFSET, VERSION_MASK},
    error::{SigningError, VerifyError},
    signature::{sign_ecdsa, verify_signature},
    traits::{DoughnutVerify, Signing},
};
use codec::{Decode, Encode, Input, Output};
use core::convert::{TryFrom, TryInto};

const NOT_BEFORE_MASK: u8 = 0b0000_0001;

const MAX_DOMAINS: usize = 128;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DoughnutV1 {
    pub issuer: [u8; 33],
    pub holder: [u8; 33],
    pub fee_mode: u8,
    pub domains: Vec<(String, Vec<u8>)>,
    pub expiry: u32,
    pub not_before: u32,
    pub payload_version: u16,
    pub signature_version: u8,
    pub signature: [u8; 64],
}

impl Default for DoughnutV1 {
    fn default() -> Self {
        DoughnutV1 {
            issuer: [0u8; 33],
            holder: [0u8; 33],
            fee_mode: 0,
            domains: Vec::<(String, Vec<u8>)>::new(),
            expiry: 0,
            not_before: 0,
            payload_version: PayloadVersion::V1 as u16,
            signature_version: SignatureVersion::ECDSA as u8,
            signature: [0u8; 64],
        }
    }
}

impl DoughnutV1 {
    /// Encodes the doughnut into an byte array and writes the result into a given memory
    /// if `encode_signature` is false, the final signature bytes are not included in the result
    fn encode_to_with_signature_optional<T: Output + ?Sized>(
        &self,
        dest: &mut T,
        encode_signature: bool,
    ) {
        // Defensive early return when there are no domains
        if self.domains.is_empty() || self.domains.len() > MAX_DOMAINS {
            return;
        }
        let domain_count = u8::try_from(self.domains.len() - 1);
        if domain_count.is_err() {
            return;
        }

        let mut version_data = self.payload_version & VERSION_MASK;

        version_data |= u16::from(self.signature_version & SIGNATURE_MASK) << SIGNATURE_OFFSET;
        dest.write(&version_data.to_le_bytes());

        let mut domain_count_and_not_before_byte = domain_count.unwrap() << 1;

        if self.not_before > 0 {
            domain_count_and_not_before_byte |= NOT_BEFORE_MASK;
        }
        dest.push_byte(domain_count_and_not_before_byte);
        dest.write(&self.issuer);
        dest.write(&self.holder);
        dest.push_byte(self.fee_mode);

        for b in &self.expiry.to_le_bytes() {
            dest.push_byte(*b);
        }

        if self.not_before > 0 {
            for b in &self.not_before.to_le_bytes() {
                dest.push_byte(*b);
            }
        }

        // Write permission domain headers
        for (key, payload) in &self.domains {
            let mut key_buf = [0_u8; 16];
            let length = key_buf.len().min(key.len());
            key_buf[..length].clone_from_slice(&key.as_bytes()[..length]);
            dest.write(&key_buf);
            for b in &(payload.len() as u16).to_le_bytes() {
                dest.push_byte(*b);
            }
        }

        // Write permission domain payloads
        for (_, payload) in &self.domains {
            dest.write(payload);
        }

        if encode_signature {
            dest.write(self.signature.as_slice());
        }
    }
}

impl Encode for DoughnutV1 {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.encode_to_with_signature_optional(dest, true);
    }
}

impl codec::EncodeLike for DoughnutV1 {}

impl Decode for DoughnutV1 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let version_data = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);

        let payload_version = version_data & VERSION_MASK;

        let signature_version = ((version_data >> SIGNATURE_OFFSET) as u8) & SIGNATURE_MASK;

        let domain_count_and_not_before_byte = input.read_byte()?;
        let permission_domain_count = (domain_count_and_not_before_byte >> 1) + 1;
        let has_not_before =
            (domain_count_and_not_before_byte & NOT_BEFORE_MASK) == NOT_BEFORE_MASK;

        let mut issuer: [u8; 33] = [0_u8; 33];
        let _ = input.read(&mut issuer);

        let mut holder: [u8; 33] = [0_u8; 33];
        let _ = input.read(&mut holder);

        let fee_mode = input.read_byte()?;

        let expiry = u32::from_le_bytes([
            input.read_byte()?,
            input.read_byte()?,
            input.read_byte()?,
            input.read_byte()?,
        ]);

        let not_before = if has_not_before {
            u32::from_le_bytes([
                input.read_byte()?,
                input.read_byte()?,
                input.read_byte()?,
                input.read_byte()?,
            ])
        } else {
            0
        };

        // Build domain permissions list
        let mut domains: Vec<(String, Vec<u8>)> = Vec::default();
        // A queue for domain keys and lengths from the domains header section
        // We use this to order later reads from the domain payload section since we
        // are restricted by `input` to read the payload byte-by-byte
        let mut q: Vec<(String, usize)> = Vec::default();

        for _ in 0..permission_domain_count {
            let mut key_buf: [u8; 16] = Default::default();
            let _ = input.read(&mut key_buf);
            let key = core::str::from_utf8(&key_buf)
                .map_err(|_| codec::Error::from("domain keys should be utf8 encoded"))?
                .trim_matches(char::from(0))
                .to_string();

            let payload_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q {
            let mut payload = alloc::vec![0; payload_length as usize];
            input.read(&mut payload)?;
            domains.push((key, payload));
        }

        let mut signature = [0_u8; 64];
        input.read(&mut signature)?;

        Ok(Self {
            holder,
            issuer,
            fee_mode,
            expiry,
            not_before,
            signature_version,
            payload_version,
            domains,
            signature,
        })
    }
}

impl DecodeInner for DoughnutV1 {
    fn decode_inner<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let payload_version = PayloadVersion::V1 as u16;
        let signature_version = SignatureVersion::ECDSA as u8;

        let domain_count_and_not_before_byte = input.read_byte()?;
        let permission_domain_count = (domain_count_and_not_before_byte >> 1) + 1;
        let has_not_before =
            (domain_count_and_not_before_byte & NOT_BEFORE_MASK) == NOT_BEFORE_MASK;

        let mut issuer: [u8; 33] = [0_u8; 33];
        let _ = input.read(&mut issuer);

        let mut holder: [u8; 33] = [0_u8; 33];
        let _ = input.read(&mut holder);

        let fee_mode = input.read_byte()?;

        let expiry = u32::from_le_bytes([
            input.read_byte()?,
            input.read_byte()?,
            input.read_byte()?,
            input.read_byte()?,
        ]);

        let not_before = if has_not_before {
            u32::from_le_bytes([
                input.read_byte()?,
                input.read_byte()?,
                input.read_byte()?,
                input.read_byte()?,
            ])
        } else {
            0
        };

        // Build domain permissions list
        let mut domains: Vec<(String, Vec<u8>)> = Vec::default();
        // A queue for domain keys and lengths from the domains header section
        // We use this to order later reads from the domain payload section since we
        // are restricted by `input` to read the payload byte-by-byte
        let mut q: Vec<(String, usize)> = Vec::default();

        for _ in 0..permission_domain_count {
            let mut key_buf: [u8; 16] = Default::default();
            let _ = input.read(&mut key_buf);
            let key = core::str::from_utf8(&key_buf)
                .map_err(|_| codec::Error::from("domain keys should be utf8 encoded"))?
                .trim_matches(char::from(0))
                .to_string();

            let payload_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q {
            let mut payload = alloc::vec![0; payload_length as usize];
            input.read(&mut payload)?;
            domains.push((key, payload));
        }

        let mut signature = [0_u8; 64];
        input.read(&mut signature)?;

        Ok(Self {
            holder,
            issuer,
            fee_mode,
            expiry,
            not_before,
            signature_version,
            payload_version,
            domains,
            signature,
        })
    }
}

impl DoughnutApi for DoughnutV1 {
    type PublicKey = [u8; 33];
    type Timestamp = u32;
    type Signature = [u8; 64];
    /// Return the doughnut holder account ID
    fn holder(&self) -> Self::PublicKey {
        self.holder
    }
    /// Return the doughnut issuer account ID
    fn issuer(&self) -> Self::PublicKey {
        self.issuer
    }
    /// Return the doughnut fee mode
    fn fee_mode(&self) -> u8 {
        self.fee_mode
    }
    /// Return the doughnut expiry timestamp
    fn expiry(&self) -> Self::Timestamp {
        self.expiry
    }
    /// Return the doughnut 'not before' timestamp
    fn not_before(&self) -> Self::Timestamp {
        self.not_before
    }
    /// Return the doughnut payload bytes
    fn payload(&self) -> Vec<u8> {
        let mut r = Vec::with_capacity(self.size_hint());
        self.encode_to_with_signature_optional(&mut r, false);
        r
    }
    /// Return the doughnut signature bytes
    fn signature(&self) -> Self::Signature {
        self.signature
    }
    /// Return the doughnut signature version
    fn signature_version(&self) -> u8 {
        self.signature_version
    }
    /// Return the payload by `domain` key, if it exists in this doughnut
    fn get_domain(&self, domain: &str) -> Option<&[u8]> {
        for (key, payload) in &self.domains {
            if key == domain {
                return Some(&payload);
            }
        }
        None
    }
}

impl DoughnutVerify for DoughnutV1 {
    fn verify(&self) -> Result<(), VerifyError> {
        verify_signature(
            self.signature_version(),
            &self.signature(),
            &self.issuer(),
            &self.payload(),
        )
    }
}

impl Signing for DoughnutV1 {
    fn sign_ed25519(&mut self, _secret_key: &[u8; 32]) -> Result<[u8; 64], SigningError> {
        Err(SigningError::NotSupported)
    }

    fn sign_sr25519(&mut self, _secret_key: &[u8; 64]) -> Result<[u8; 64], SigningError> {
        Err(SigningError::NotSupported)
    }

    fn sign_ecdsa(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 64], SigningError> {
        sign_ecdsa(secret_key, &self.payload()).map(|signature| {
            self.signature = signature;
            signature
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ValidationError;
    use std::{
        ops::Add,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    macro_rules! doughnut_builder {
        (
            issuer:$issuer:expr,
            holder:$holder:expr,
            fee_mode:$fee_mode:expr,
            domains:$domains:expr,
            expiry:$expiry:expr,
            not_before:$not_before:expr,
            payload_version:$pv:expr,
            signature_version:$sv:expr,
            signature:$signature:expr,
        ) => {
            DoughnutV1 {
                issuer: $issuer,
                holder: $holder,
                fee_mode: $fee_mode,
                domains: $domains,
                expiry: $expiry,
                not_before: $not_before,
                payload_version: $pv,
                signature_version: $sv,
                signature: $signature,
            }
        };
        (
            holder: $holder:expr,
            expiry:$expiry:expr,
            not_before:$not_before:expr,
        ) => {
            doughnut_builder!(
                issuer:[0_u8; 33],
                holder:$holder,
                fee_mode: 0,
                domains:vec![("cennznet".to_string(), vec![0])],
                expiry: $expiry,
                not_before: $not_before,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 64],
            )
        };
        (
            holder: $holder:expr,
            expiry:$expiry:expr,
            not_before:$not_before:expr,
            fee_mode:$fee_mode:expr,
        ) => {
            doughnut_builder!(
                issuer:[0_u8; 33],
                holder:$holder,
                fee_mode: $fee_mode,
                domains:vec![("cennznet".to_string(), vec![0])],
                expiry: $expiry,
                not_before: $not_before,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 64],
            )
        };
        (
            payload_version: $pv:expr,
            signature_version: $sv:expr,
        ) => {
            doughnut_builder!(
                issuer:[0_u8; 33],
                holder:[1_u8; 33],
                fee_mode: 0,
                domains:vec![("cennznet".to_string(), vec![0])],
                expiry: 0,
                not_before: 0,
                payload_version: $pv,
                signature_version: $sv,
                signature: [0xa5; 64],
            )
        };
        (
            domains:$domains:expr,
        ) => {
            doughnut_builder!(
                issuer: [0_u8; 33],
                holder: [1_u8; 33],
                fee_mode: 0,
                domains: $domains,
                expiry: 0,
                not_before: 0,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 64],
            )
        };
        (holder: $holder:expr,) => {
            doughnut_builder!(
                holder: $holder,
                expiry: 0,
                not_before: 0,
            )
        };
        () => { doughnut_builder!(holder: [1_u8; 33],) };
    }

    // Make a unix timestamp `when` seconds from the invocation
    fn make_unix_timestamp(seconds: u64) -> u32 {
        SystemTime::now()
            .add(Duration::from_secs(seconds))
            .duration_since(UNIX_EPOCH)
            .expect("it works")
            .as_millis() as u32
    }

    #[test]
    fn it_is_a_valid_usage() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(
            holder: holder,
            expiry: make_unix_timestamp(10),
            not_before: 0,
        );

        assert!(doughnut.validate(holder, make_unix_timestamp(0)).is_ok())
    }

    #[test]
    fn usage_after_expiry_is_invalid() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(
            holder: holder,
            expiry: 0,
            not_before: 0,
        );

        assert_eq!(
            doughnut.validate(holder, make_unix_timestamp(5)),
            Err(ValidationError::Expired)
        )
    }

    #[test]
    fn usage_by_non_holder_is_invalid() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(holder: holder,);

        let not_the_holder = [2_u8; 33];
        assert_eq!(
            doughnut.validate(not_the_holder, make_unix_timestamp(0)),
            Err(ValidationError::HolderIdentityMismatched)
        )
    }

    #[test]
    fn usage_preceding_not_before_is_invalid() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(
            holder: holder,
            expiry: make_unix_timestamp(12),
            not_before: make_unix_timestamp(10),
        );

        assert_eq!(
            doughnut.validate(holder, make_unix_timestamp(0)),
            Err(ValidationError::Premature)
        )
    }

    #[test]
    fn validate_with_timestamp_overflow_fails() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(
            holder: holder,
            expiry: 0,
            not_before: 0,
        );

        assert_eq!(
            doughnut.validate(holder, u64::max_value()),
            Err(ValidationError::Conversion)
        )
    }

    #[test]
    fn versions_encode_and_decode() {
        let doughnut = doughnut_builder!(
            payload_version: 0x0515,
            signature_version: 0x1a,
        );

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.signature_version, 0x1a);
        assert_eq!(parsed_doughnut.payload_version, 0x0515);
    }

    #[test]
    fn payload_version_does_not_cross_contaminate() {
        let doughnut = doughnut_builder!(
            payload_version: 0xffff,
            signature_version: 0x00,
        );

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.signature_version, 0x00);
        assert_eq!(parsed_doughnut.payload_version, VERSION_MASK);
    }

    #[test]
    fn signature_version_does_not_cross_contaminate() {
        let doughnut = doughnut_builder!(
            payload_version: 0x0000,
            signature_version: 0xff,
        );

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.payload_version, 0x0000);
        assert_eq!(parsed_doughnut.signature_version, 0x1f);
    }

    // #[test]
    // fn decode_from_u8_array() {
    //     let issuer = vec![
    //         150u8, 22, 44, 205, 2, 222, 76, 191, 190, 171, 49, 135, 116, 73, 75, 214, 129, 172,
    //         123, 53, 115, 170, 24, 156, 51, 98, 166, 110, 214, 167, 219, 123,
    //     ];
    //     let holder = vec![
    //         27u8, 137, 65, 29, 182, 25, 157, 61, 226, 13, 230, 14, 111, 6, 25, 186, 227, 117, 177,
    //         244, 172, 147, 40, 119, 209, 78, 13, 109, 236, 119, 205, 202,
    //     ];
    //     let signature = vec![
    //         90u8, 143, 31, 88, 7, 153, 88, 176, 209, 39, 71, 65, 16, 116, 95, 143, 125, 99, 21, 60,
    //         109, 250, 196, 2, 107, 14, 164, 101, 110, 235, 151, 76, 136, 156, 88, 112, 164, 29, 68,
    //         185, 16, 246, 206, 52, 94, 190, 226, 158, 201, 110, 81, 253, 184, 118, 189, 149, 226,
    //         203, 63, 146, 23, 217, 177, 9,
    //     ];

    //     let mut encoded_doughnut = vec![0u8, 8, 3];
    //     encoded_doughnut.append(&mut issuer.clone());
    //     encoded_doughnut.append(&mut holder.clone());
    //     encoded_doughnut.append(&mut vec![
    //         177u8, 104, 222, 58, 57, 48, 0, 0, 68, 111, 109, 97, 105, 110, 32, 49, 0, 0, 0, 0, 0,
    //         0, 0, 0, 10, 0, 68, 111, 109, 97, 105, 110, 32, 50, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1,
    //         2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    //     ]);
    //     encoded_doughnut.append(&mut signature.clone());

    //     let decoded_doughnut = DoughnutV1::decode(&mut &encoded_doughnut[..]).unwrap();
    //     assert_eq!(decoded_doughnut.signature_version(), 1);
    //     assert_eq!(decoded_doughnut.not_before(), 12345);
    //     assert_eq!(decoded_doughnut.expiry(), 987654321);
    //     assert_eq!(Vec::from(&decoded_doughnut.holder() as &[u8]), holder);
    //     assert_eq!(Vec::from(&decoded_doughnut.issuer() as &[u8]), issuer);
    //     assert_eq!(Vec::from(&decoded_doughnut.signature() as &[u8]), signature);
    // }

    #[test]
    fn no_domains_fails_encoding() {
        let doughnut = doughnut_builder!(domains: vec![],);

        let encoded = doughnut.encode();
        assert_eq!(encoded, Vec::<u8>::new());
    }

    #[test]
    fn too_many_domains_fails_encoding() {
        let mut domains: Vec<(String, Vec<u8>)> = vec![];
        for x in 0..MAX_DOMAINS + 1 {
            domains.push((x.to_string(), vec![]));
        }

        let doughnut = doughnut_builder!(domains: domains,);

        let encoded = doughnut.encode();
        assert_eq!(encoded, Vec::<u8>::new());
    }

    // #[test]
    // fn can_encode_up_to_max_domains() {
    //     let mut domains: Vec<(String, Vec<u8>)> = vec![];
    //     for x in 0..MAX_DOMAINS {
    //         domains.push((x.to_string(), vec![]));
    //     }

    //     let doughnut = doughnut_builder!(domains: domains,);

    //     let encoded = doughnut.encode();
    //     let expected_length = 135 + (18 * MAX_DOMAINS);

    //     assert_eq!(encoded.len(), expected_length);
    // }

    #[test]
    fn short_domain_name_is_parsed() {
        let doughnut = doughnut_builder!(domains: vec![("Smol".to_string(), vec![])],);

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.domains[0].0, "Smol");
    }

    #[test]
    fn long_domain_name_is_truncated() {
        let doughnut =
            doughnut_builder!(domains: vec![("SweetLikeAChic-a-CherryCola".to_string(), vec![])],);

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.domains[0].0, "SweetLikeAChic-a");
    }

    #[test]
    fn full_encode_and_decode_works() {
        let domains = vec![
            (
                "Come".to_string(),
                vec![0x42, 0x72, 0x65, 0x61, 0x74, 0x68, 0x65],
            ),
            (
                "stand".to_string(),
                vec![0x69, 0x6e, 0x20, 0x61, 0x6e, 0x64],
            ),
            ("a".to_string(), vec![0x67, 0x65, 0x74]),
            ("little".to_string(), vec![0x61]),
            ("bit".to_string(), vec![0x62, 0x69, 0x74]),
            (
                "closer".to_string(),
                vec![0x68, 0x69, 0x67, 0x68, 0x65, 0x72],
            ),
        ];
        let doughnut = doughnut_builder! (
            issuer: [0x55_u8; 33],
            holder: [0x88_u8; 33],
            fee_mode: 0x0,
            domains: domains,
            expiry: 0x1234,
            not_before: 0x5678,
            payload_version: 0xab,
            signature_version: 0xc,
            signature: [0xa5; 64],
        );

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();

        assert_eq!(doughnut, parsed_doughnut);
    }

    #[test]
    fn decode_error_with_missing_byte() {
        let doughnut = doughnut_builder!();
        let encoded = doughnut.encode();
        let length = encoded.len() - 1;

        let result = DoughnutV1::decode(&mut &encoded[..length]);

        assert_eq!(
            result,
            Err(codec::Error::from("Not enough data to fill buffer"))
        );
    }

    #[test]
    fn decode_error_with_no_bytes() {
        let encoded = [];

        let result = DoughnutV1::decode(&mut &encoded[..]);

        assert_eq!(
            result,
            Err(codec::Error::from("Not enough data to fill buffer"))
        );
    }

    #[test]
    fn decode_error_with_too_many_bytes() {
        let doughnut = doughnut_builder!();
        let encoded = doughnut.encode();
        let encoded = vec![encoded, vec![0x00]].concat();

        let result = DoughnutV1::decode(&mut &encoded[..]);

        // This used to be a decoding error.
        // It may be desirable for some use cases to fail when encountering extraneous bytes
        // as a security precaution.
        // TODO: reconcile with https://github.com/cennznet/doughnut-rs/issues/67
        assert!(result.is_ok());
    }

    // #[test]
    // fn decode_error_with_bad_domain_character() {
    //     let doughnut = doughnut_builder!();
    //     let mut encoded = doughnut.encode();
    //     encoded[72] = 0xff; //invalid utf-8

    //     let result = DoughnutV1::decode(&mut &encoded[..]);

    //     assert_eq!(
    //         result,
    //         Err(codec::Error::from("domain keys should be utf8 encoded"))
    //     );
    // }

    // #[test]
    // fn decode_error_with_incorrect_domain_length() {
    //     let doughnut = doughnut_builder!(domains: vec![("ZeroLength".to_string(), vec![])],);
    //     let mut encoded = doughnut.encode();
    //     encoded[72 + 16] = 0xff; //invalid utf-8

    //     let result = DoughnutV1::decode(&mut &encoded[..]);
    //     assert_eq!(
    //         result,
    //         Err(codec::Error::from("Not enough data to fill buffer"))
    //     );
    // }

    #[test]
    fn holder_as_fee_mode_encode_and_decode() {
        let holder = [1_u8; 33];
        let doughnut = doughnut_builder!(
            holder: holder,
            expiry: 0,
            not_before: 0,
            fee_mode: 1, // holder pays the fee
        );

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.holder, holder);
        assert_eq!(parsed_doughnut.expiry, 0);
        assert_eq!(parsed_doughnut.not_before, 0);
        assert_eq!(parsed_doughnut.fee_mode, 1);
        assert_eq!(parsed_doughnut.fee_payer(), holder);
    }

    #[test]
    fn inner_decode_works() {
        let payload_version = PayloadVersion::V1; // default value for v1
        let signature_version = SignatureVersion::ECDSA; // // default value for v1
        let doughnut = doughnut_builder!(
            payload_version: payload_version as u16,
            signature_version: signature_version as u8,
        );

        let mut full_encoded_payload = doughnut.encode();
        //split to segregate version info
        let (version_info, inner_payload) = full_encoded_payload.split_at(2);

        let parsed_doughnut = DoughnutV1::decode_inner(&mut inner_payload.clone()).unwrap();
        assert_eq!(doughnut, parsed_doughnut);
    }
}