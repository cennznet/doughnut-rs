// Copyright 2023-2024 Futureverse Corporation Limited

//!
//! Doughnut V1 codec
//! This version is for interoperability within the substrate extrinsic environment.
//! It uses the `codec` crate to consume a contiguous stream of bytes, without any look-ahead.
//! It however, does not use the SCALE codec.

#![allow(clippy::cast_possible_truncation)]

#[cfg(feature = "crypto")]
use crate::signature::crypto::{sign_ecdsa, sign_eip191, verify_signature};
use crate::signature::SignatureVersion;
use crate::traits::{DecodeInner, DoughnutApi, PayloadVersion};
use crate::{
    alloc::{
        string::{String, ToString},
        vec::Vec,
    },
    doughnut::{SIGNATURE_MASK, SIGNATURE_OFFSET, VERSION_MASK},
};
#[cfg(feature = "crypto")]
use crate::{
    error::{SigningError, VerifyError},
    traits::{DoughnutVerify, Signing},
};

use codec::{Decode, Encode, Input, Output};
use core::convert::TryFrom;

const NOT_BEFORE_MASK: u8 = 0b0000_0001;

const MAX_TOPPINGS: usize = 128;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DoughnutV1 {
    pub issuer: [u8; 33],
    pub holder: [u8; 33],
    pub fee_mode: u8,
    pub toppings: Vec<(String, Vec<u8>)>,
    pub expiry: u32,
    pub not_before: u32,
    pub payload_version: u16,
    pub signature_version: u8,
    pub signature: [u8; 65],
}

impl Default for DoughnutV1 {
    fn default() -> Self {
        DoughnutV1 {
            issuer: [0u8; 33],
            holder: [0u8; 33],
            fee_mode: 0,
            toppings: Vec::<(String, Vec<u8>)>::new(),
            expiry: 0,
            not_before: 0,
            payload_version: PayloadVersion::V1 as u16,
            signature_version: SignatureVersion::EIP191 as u8,
            signature: [0u8; 65],
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
        // Defensive early return when there are no toppings
        if self.toppings.is_empty() || self.toppings.len() > MAX_TOPPINGS {
            return;
        }
        let topping_count = u8::try_from(self.toppings.len() - 1);
        if topping_count.is_err() {
            return;
        }

        let mut version_data = self.payload_version & VERSION_MASK;

        version_data |= u16::from(self.signature_version & SIGNATURE_MASK) << SIGNATURE_OFFSET;
        dest.write(&version_data.to_le_bytes());

        let mut topping_count_and_not_before_byte = topping_count.unwrap() << 1;

        if self.not_before > 0 {
            topping_count_and_not_before_byte |= NOT_BEFORE_MASK;
        }
        dest.push_byte(topping_count_and_not_before_byte);
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

        // Write permission topping headers
        for (key, payload) in &self.toppings {
            let mut key_buf = [0_u8; 16];
            let length = key_buf.len().min(key.len());
            key_buf[..length].clone_from_slice(&key.as_bytes()[..length]);
            dest.write(&key_buf);
            for b in &(payload.len() as u16).to_le_bytes() {
                dest.push_byte(*b);
            }
        }

        // Write permission topping payloads
        for (_, payload) in &self.toppings {
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

        let topping_count_and_not_before_byte = input.read_byte()?;
        let permission_topping_count = (topping_count_and_not_before_byte >> 1) + 1;
        let has_not_before =
            (topping_count_and_not_before_byte & NOT_BEFORE_MASK) == NOT_BEFORE_MASK;

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

        // Build topping permissions list
        let mut toppings: Vec<(String, Vec<u8>)> = Vec::default();
        // A queue for topping keys and lengths from the toppings header section
        // We use this to order later reads from the topping payload section since we
        // are restricted by `input` to read the payload byte-by-byte
        let mut q: Vec<(String, usize)> = Vec::default();

        for _ in 0..permission_topping_count {
            let mut key_buf: [u8; 16] = Default::default();
            let _ = input.read(&mut key_buf);
            let key = core::str::from_utf8(&key_buf)
                .map_err(|_| codec::Error::from("topping keys should be utf8 encoded"))?
                .trim_matches(char::from(0))
                .to_string();

            let payload_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q {
            let mut payload = alloc::vec![0; payload_length as usize];
            input.read(&mut payload)?;
            toppings.push((key, payload));
        }

        let mut signature = [0_u8; 65];
        input.read(&mut signature)?;

        Ok(Self {
            holder,
            issuer,
            fee_mode,
            expiry,
            not_before,
            signature_version,
            payload_version,
            toppings,
            signature,
        })
    }
}

impl DecodeInner for DoughnutV1 {
    fn decode_inner<I: Input>(
        input: &mut I,
        with_version_info: bool,
    ) -> Result<Self, codec::Error> {
        let mut payload_version = PayloadVersion::V1 as u16;
        let mut signature_version = SignatureVersion::ECDSA as u8;

        if with_version_info {
            let version_data = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            payload_version = version_data & VERSION_MASK;
            signature_version = ((version_data >> SIGNATURE_OFFSET) as u8) & SIGNATURE_MASK;
        }

        let topping_count_and_not_before_byte = input.read_byte()?;
        let permission_topping_count = (topping_count_and_not_before_byte >> 1) + 1;
        let has_not_before =
            (topping_count_and_not_before_byte & NOT_BEFORE_MASK) == NOT_BEFORE_MASK;

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

        // Build topping permissions list
        let mut toppings: Vec<(String, Vec<u8>)> = Vec::default();
        // A queue for topping keys and lengths from the toppings header section
        // We use this to order later reads from the topping payload section since we
        // are restricted by `input` to read the payload byte-by-byte
        let mut q: Vec<(String, usize)> = Vec::default();

        for _ in 0..permission_topping_count {
            let mut key_buf: [u8; 16] = Default::default();
            let _ = input.read(&mut key_buf);
            let key = core::str::from_utf8(&key_buf)
                .map_err(|_| codec::Error::from("topping keys should be utf8 encoded"))?
                .trim_matches(char::from(0))
                .to_string();

            let payload_length = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q {
            let mut payload = alloc::vec![0; payload_length as usize];
            input.read(&mut payload)?;
            toppings.push((key, payload));
        }

        let mut signature = [0_u8; 65];
        input.read(&mut signature)?;

        Ok(Self {
            holder,
            issuer,
            fee_mode,
            expiry,
            not_before,
            signature_version,
            payload_version,
            toppings,
            signature,
        })
    }
}

impl DoughnutApi for DoughnutV1 {
    type PublicKey = [u8; 33];
    type Timestamp = u32;
    type Signature = [u8; 65];
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
    /// Return the payload by `topping` key, if it exists in this doughnut
    fn get_topping(&self, topping: &str) -> Option<&[u8]> {
        for (key, payload) in &self.toppings {
            if key == topping {
                return Some(&payload);
            }
        }
        None
    }
}

#[cfg(feature = "crypto")]
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

#[cfg(feature = "crypto")]
impl Signing for DoughnutV1 {
    fn sign_ed25519(&mut self, _secret_key: &[u8; 32]) -> Result<[u8; 64], SigningError> {
        Err(SigningError::NotSupported)
    }

    fn sign_sr25519(&mut self, _secret_key: &[u8; 64]) -> Result<[u8; 64], SigningError> {
        Err(SigningError::NotSupported)
    }

    fn sign_ecdsa(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 65], SigningError> {
        sign_ecdsa(secret_key, &self.payload()).map(|signature| {
            self.signature_version = SignatureVersion::ECDSA as u8;
            self.signature = signature;
            signature
        })
    }

    fn sign_eip191(&mut self, secret_key: &[u8; 32]) -> Result<[u8; 65], SigningError> {
        sign_eip191(secret_key, &self.payload()).map(|signature| {
            self.signature_version = SignatureVersion::EIP191 as u8;
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
            toppings:$toppings:expr,
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
                toppings: $toppings,
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
                toppings:vec![("trn".to_string(), vec![0])],
                expiry: $expiry,
                not_before: $not_before,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 65],
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
                toppings:vec![("trn".to_string(), vec![0])],
                expiry: $expiry,
                not_before: $not_before,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 65],
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
                toppings:vec![("trn".to_string(), vec![0])],
                expiry: 0,
                not_before: 0,
                payload_version: $pv,
                signature_version: $sv,
                signature: [0xa5; 65],
            )
        };
        (
            toppings:$toppings:expr,
        ) => {
            doughnut_builder!(
                issuer: [0_u8; 33],
                holder: [1_u8; 33],
                fee_mode: 0,
                toppings: $toppings,
                expiry: 0,
                not_before: 0,
                payload_version: 0,
                signature_version: 0,
                signature: [0xa5; 65],
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

    #[test]
    fn no_toppings_fails_encoding() {
        let doughnut = doughnut_builder!(toppings: vec![],);

        let encoded = doughnut.encode();
        assert_eq!(encoded, Vec::<u8>::new());
    }

    #[test]
    fn too_many_toppings_fails_encoding() {
        let mut toppings: Vec<(String, Vec<u8>)> = vec![];
        for x in 0..MAX_TOPPINGS + 1 {
            toppings.push((x.to_string(), vec![]));
        }

        let doughnut = doughnut_builder!(toppings: toppings,);

        let encoded = doughnut.encode();
        assert_eq!(encoded, Vec::<u8>::new());
    }

    #[test]
    fn short_topping_name_is_parsed() {
        let doughnut = doughnut_builder!(toppings: vec![("Smol".to_string(), vec![])],);

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.toppings[0].0, "Smol");
    }

    #[test]
    fn long_topping_name_is_truncated() {
        let doughnut =
            doughnut_builder!(toppings: vec![("SweetLikeAChic-a-CherryCola".to_string(), vec![])],);

        let parsed_doughnut = DoughnutV1::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.toppings[0].0, "SweetLikeAChic-a");
    }

    #[test]
    fn full_encode_and_decode_works() {
        let toppings = vec![
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
            toppings: toppings,
            expiry: 0x1234,
            not_before: 0x5678,
            payload_version: 0xab,
            signature_version: 0xc,
            signature: [0xa5; 65],
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

    #[test]
    fn decode_error_with_bad_topping_character() {
        let doughnut = doughnut_builder!();
        let mut encoded = doughnut.encode();
        encoded[76] = 0xff; //invalid utf-8

        let result = DoughnutV1::decode(&mut &encoded[..]);

        assert_eq!(
            result,
            Err(codec::Error::from("topping keys should be utf8 encoded"))
        );
    }

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

        let full_encoded_payload = doughnut.encode();
        // decode full encoded payload with version info
        let parsed_doughnut_1 =
            DoughnutV1::decode_inner(&mut full_encoded_payload.clone().as_slice(), true).unwrap();
        assert_eq!(doughnut, parsed_doughnut_1);

        //split to segregate version info
        let (_version_info, inner_payload) = full_encoded_payload.split_at(2);

        let parsed_doughnut_2 =
            DoughnutV1::decode_inner(&mut inner_payload.clone(), false).unwrap();
        assert_eq!(doughnut, parsed_doughnut_2);
    }
}
