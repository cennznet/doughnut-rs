// Copyright 2019 Centrality Investments Limited

//!
//! Doughnut V0 codec
//! This version is for interoperability within the substrate extrinsic environment.
//! It uses the `codec` crate to consume a contiguous stream of bytes, without any look-ahead.
//! It however, does not use the SCALE codec.

#![allow(clippy::cast_possible_truncation)]

use bit_reverse::ParallelReverse;
use codec::{Decode, Encode, Input, Output};
use primitive_types::H512;

use crate::alloc::{
    string::{String, ToString},
    vec::Vec,
};
use crate::traits::DoughnutApi;

const NOT_BEFORE_MASK: u8 = 0b1000_0000;
const SIGNATURE_MASK: u8 = 0b1111_1000;
const VERSION_UPPER_MASK: u8 = 0b0000_0111;
const VERSION_11BIT_MASK: u16 = 0b0000_0111_1111_1111;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DoughnutV0 {
    pub issuer: [u8; 32],
    pub holder: [u8; 32],
    pub domains: Vec<(String, Vec<u8>)>,
    pub expiry: u32,
    pub not_before: u32,
    pub payload_version: u16,
    pub signature_version: u8,
    pub signature: H512,
}

impl DoughnutV0 {
    /// Encodes the doughnut into an byte array and writes the result into a given memory
    /// if `encode_signature` is false, the final signature bytes are not included in the result
    fn encode_to_with_signature_optional<T: Output>(&self, dest: &mut T, encode_signature: bool) {
        let mut payload_version_and_signature_version =
            (self.payload_version & VERSION_11BIT_MASK).swap_bits();

        payload_version_and_signature_version |=
            u16::from(self.signature_version & 0x1f).swap_bits() >> 11;
        dest.write(&payload_version_and_signature_version.to_be_bytes());

        let mut domain_count_and_not_before_byte =
            (((self.domains.len() as u8) - 1) << 1).swap_bits();
        if self.not_before > 0 {
            domain_count_and_not_before_byte |= NOT_BEFORE_MASK;
        }
        dest.push_byte(domain_count_and_not_before_byte);
        dest.write(&self.issuer);
        dest.write(&self.holder);

        for b in &self.expiry.to_le_bytes() {
            dest.push_byte(b.swap_bits());
        }

        if self.not_before > 0 {
            for b in &self.not_before.to_le_bytes() {
                dest.push_byte(b.swap_bits());
            }
        }

        // Write permission domain headers
        for (key, payload) in &self.domains {
            let mut key_buf = [0_u8; 16];
            key_buf[..key.len()].clone_from_slice(&key.as_bytes());
            dest.write(&key_buf);
            for b in &(payload.len() as u16).to_le_bytes() {
                dest.push_byte(b.swap_bits());
            }
        }

        // Write permission domain payloads
        for (_, payload) in &self.domains {
            dest.write(payload);
        }

        if encode_signature {
            dest.write(self.signature.as_bytes());
        }
    }
}
impl Encode for DoughnutV0 {
    fn encode_to<T: Output>(&self, dest: &mut T) {
        self.encode_to_with_signature_optional(dest, true);
    }
}

impl codec::EncodeLike for DoughnutV0 {}

impl DoughnutApi for DoughnutV0 {
    type PublicKey = [u8; 32];
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
        self.signature.into()
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

impl Decode for DoughnutV0 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let version_byte_0 = input.read_byte()?.swap_bits();
        let version_byte_1 = input.read_byte()?.swap_bits();

        let payload_version =
            u16::from_le_bytes([version_byte_0, version_byte_1 & VERSION_UPPER_MASK]);

        let signature_version = (version_byte_1 & SIGNATURE_MASK) >> 3;

        let domain_count_and_not_before_byte = input.read_byte()?;
        let permission_domain_count = (domain_count_and_not_before_byte.swap_bits() >> 1) + 1;
        let has_not_before =
            (domain_count_and_not_before_byte & NOT_BEFORE_MASK) == NOT_BEFORE_MASK;

        let mut issuer: [u8; 32] = Default::default();
        let _ = input.read(&mut issuer);

        let mut holder: [u8; 32] = Default::default();
        let _ = input.read(&mut holder);

        let expiry = u32::from_le_bytes([
            input.read_byte()?.swap_bits(),
            input.read_byte()?.swap_bits(),
            input.read_byte()?.swap_bits(),
            input.read_byte()?.swap_bits(),
        ]);

        let not_before = if has_not_before {
            u32::from_le_bytes([
                input.read_byte()?.swap_bits(),
                input.read_byte()?.swap_bits(),
                input.read_byte()?.swap_bits(),
                input.read_byte()?.swap_bits(),
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

            let payload_length = u16::from_le_bytes([
                input.read_byte()?.swap_bits(),
                input.read_byte()?.swap_bits(),
            ]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q {
            let mut payload = Vec::with_capacity(payload_length);
            unsafe {
                payload.set_len(payload_length);
            }
            let _ = input.read(&mut payload);
            domains.push((key, payload));
        }

        let mut signature = [0_u8; 64];
        let _ = input.read(&mut signature);

        Ok(Self {
            holder,
            issuer,
            expiry,
            not_before,
            signature_version,
            payload_version,
            domains,
            signature: H512::from(signature),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ValidationError;
    use std::ops::Add;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: Vec::default(),
            expiry: make_unix_timestamp(10),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: H512::default(), // No need to check signature here
        };

        assert!(doughnut.validate(holder, make_unix_timestamp(0)).is_ok())
    }
    #[test]
    fn usage_after_expiry_is_invalid() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: Vec::default(),
            expiry: make_unix_timestamp(0),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: H512::default(), // No need to check signature here
        };

        assert_eq!(
            doughnut.validate(holder, make_unix_timestamp(5)),
            Err(ValidationError::Expired)
        )
    }
    #[test]
    fn usage_by_non_holder_is_invalid() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: Vec::default(),
            expiry: make_unix_timestamp(10),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: H512::default(), // No need to check signature here
        };

        let not_the_holder = [2_u8; 32];
        assert_eq!(
            doughnut.validate(not_the_holder, make_unix_timestamp(0)),
            Err(ValidationError::HolderIdentityMismatched)
        )
    }
    #[test]
    fn usage_preceding_not_before_is_invalid() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: Vec::default(),
            expiry: make_unix_timestamp(12),
            not_before: make_unix_timestamp(10),
            payload_version: 0,
            signature_version: 0,
            signature: H512::default(), // No need to check signature here
        };

        assert_eq!(
            doughnut.validate(holder, make_unix_timestamp(0)),
            Err(ValidationError::Premature)
        )
    }

    #[test]
    fn validate_with_timestamp_overflow_fails() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: Vec::default(),
            expiry: 0,
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: H512::default(),
        };

        assert_eq!(
            doughnut.validate(holder, u64::max_value()),
            Err(ValidationError::Conversion)
        )
    }

    #[test]
    fn versions_encode_and_decode() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: vec![("TestDomain".to_string(), vec![])],
            expiry: 0,
            not_before: 0,
            payload_version: 0x0515,
            signature_version: 0x1a,
            signature: H512::default(),
        };

        let parsed_doughnut = DoughnutV0::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.signature_version, 0x1a);
        assert_eq!(parsed_doughnut.payload_version, 0x0515);
    }

    #[test]
    fn payload_version_does_not_cross_contaminate() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: vec![("TestDomain".to_string(), vec![])],
            expiry: 0,
            not_before: 0,
            payload_version: 0xffff,
            signature_version: 0x00,
            signature: H512::default(),
        };

        let parsed_doughnut = DoughnutV0::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.signature_version, 0x00);
        assert_eq!(parsed_doughnut.payload_version, VERSION_11BIT_MASK);
    }

    #[test]
    fn signature_version_does_not_cross_contaminate() {
        let holder = [1_u8; 32];
        let doughnut = DoughnutV0 {
            issuer: [0_u8; 32],
            holder,
            domains: vec![("TestDomain".to_string(), vec![])],
            expiry: 0,
            not_before: 0,
            payload_version: 0x0000,
            signature_version: 0xff,
            signature: H512::default(),
        };

        let parsed_doughnut = DoughnutV0::decode(&mut &doughnut.encode()[..]).unwrap();
        assert_eq!(parsed_doughnut.payload_version, 0x0000);
        assert_eq!(parsed_doughnut.signature_version, 0x1f);
    }
}
