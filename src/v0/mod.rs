// Copyright 2019 Centrality Investments Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//!
//! Doughnut V0 codec
//! This codec operates on a valid byte slice, lazy-ily decoding parts when required.
//!
use bit_reverse::ParallelReverse;
use core::ptr;
use parity_codec::Encode;

#[cfg(feature = "std")]
use alloc::fmt;

use crate::alloc::vec::Vec;
use crate::error::{CodecError, ValidationError};
use crate::traits::DoughnutApi;

pub mod parity;

const VERSION: u16 = 0;
const VERSION_MASK: u16 = 0x7FF;
const SIGNATURE_LENGTH_V0: u16 = 64;
const WITHOUT_NOT_BEFORE_OFFSET: u8 = 71;
const WITH_NOT_BEFORE_OFFSET: u8 = 75;
const SIGNATURE_MASK: u8 = 0b0001_1111;
const NOT_BEFORE_MASK: u8 = 0b1000_0000;

#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct DoughnutV0<'a>(&'a [u8]);

impl<'a> DoughnutApi for DoughnutV0<'a> {
    type PublicKey = [u8; 32];
    type Timestamp = u32;
    type Signature = [u8; 64];

    /// Returns the doughnut expiry unix timestamp
    fn expiry(&self) -> Self::Timestamp {
        let offset = 67;
        u32::from_le_bytes([
            self.0[offset].swap_bits(),
            self.0[offset + 1].swap_bits(),
            self.0[offset + 2].swap_bits(),
            self.0[offset + 3].swap_bits(),
        ])
    }

    /// Returns the doughnut 'not before' unix timestamp
    fn not_before(&self) -> u32 {
        if self.has_not_before() {
            let offset = 71;
            u32::from_le_bytes([
                self.0[offset].swap_bits(),
                self.0[offset + 1].swap_bits(),
                self.0[offset + 2].swap_bits(),
                self.0[offset + 3].swap_bits(),
            ])
        } else {
            0
        }
    }

    /// Returns the doughnut holder public key
    fn holder(&self) -> Self::PublicKey {
        let offset = 35;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const Self::PublicKey) }
    }

    /// Returns the doughnut issuer public key
    fn issuer(&self) -> Self::PublicKey {
        let offset = 3;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const Self::PublicKey) }
    }

    ///Returns the doughnut payload (no signature)
    fn payload(&self) -> Vec<u8> {
        self.0[..self.0.len() - 64].to_vec()
    }

    // Returns the doughnut signature
    fn signature(&self) -> Self::Signature {
        unsafe { ptr::read(self.0[(self.0.len() - 64)..].as_ptr() as *const [u8; 64]) }
    }

    /// Returns the doughnut signature scheme version
    fn signature_version(&self) -> u8 {
        self.0[1].swap_bits() & SIGNATURE_MASK
    }

    /// Return the payload by `domain` key, if it exists in this doughnut
    fn get_domain(&self, domain: &str) -> Option<&[u8]> {
        // Dependent on 'not before' inclusion
        let mut offset = if self.has_not_before() {
            WITH_NOT_BEFORE_OFFSET
        } else {
            WITHOUT_NOT_BEFORE_OFFSET
        };

        // Scan domains
        let mut domain_offset = u16::from(offset) + (self.permission_domain_count() as u16) * 18;
        for _ in 0..self.permission_domain_count() {
            // 16 bytes per key, 2 bytes for payload length
            let domain_len = u16::from_le_bytes([
                self.0[(offset + 16) as usize].swap_bits(),
                self.0[(offset + 17) as usize].swap_bits(),
            ]);

            // TODO: Raise error on invalid UTF-8
            let key = core::str::from_utf8(&self.0[offset as usize..(offset + 16) as usize])
                .unwrap_or("<invalid>");
            let key_clean = key.trim_matches(char::from(0));
            if domain == key_clean {
                return Some(
                    &self.0[domain_offset as usize..(domain_offset + domain_len) as usize],
                );
            }
            offset += 18;
            domain_offset += domain_len;
        }

        None
    }

    /// Validate the doughnut is usable by a public key (`who`) at the current timestamp (`now`)
    fn validate(&self, who: &Self::PublicKey, now: Self::Timestamp) -> Result<(), ValidationError> {
        if who != &self.holder() {
            return Err(ValidationError::HolderIdentityMismatched);
        }
        if now < self.not_before() {
            return Err(ValidationError::Premature);
        }
        if now >= self.expiry() {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

/// Return the payload version from the given byte slice
fn payload_version(buf: &[u8]) -> u16 {
    let payload_version = u16::from_le_bytes([buf[0].swap_bits(), buf[1].swap_bits()]);
    payload_version & VERSION_MASK
}

/// Returns the doughnut "permission domain count"
fn permission_domain_count(buf: &[u8]) -> u8 {
    let count = ((buf[2] & 0b0100_0000).swap_bits() >> 1) + 1;
    count
}

/// Whether the doughnut has "not before" bit set
fn has_not_before(buf: &[u8]) -> bool {
    (buf[2] & NOT_BEFORE_MASK) == NOT_BEFORE_MASK
}

#[cfg(feature = "std")]
impl<'a> fmt::Display for DoughnutV0<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "signature version: {}\
             payload version: {}\
             issuer: {:?}\
             holder: {:?}\
             expiry: {}\
             not before: {}\
             domains: <undefined>\
             signature: {:?}",
            self.signature_version(),
            self.payload_version(),
            self.issuer(),
            self.holder(),
            self.expiry(),
            self.not_before(),
            self.signature().to_vec(),
        )
    }
}

impl<'a> DoughnutV0<'a> {
    /// Create a new v0 Doughnut from encoded bytes verifying it's correctness.
    /// Returns an error if encoding is invalid
    pub fn new(encoded: &'a [u8]) -> Result<Self, CodecError<'a>> {
        if encoded.len() < 2 {
            return Err(CodecError::BadEncoding(&"Missing header"));
        }
        if payload_version(encoded) != VERSION {
            return Err(CodecError::UnsupportedVersion);
        }

        // A crude minimum length check
        let offset = u16::from(if has_not_before(encoded) {
            WITH_NOT_BEFORE_OFFSET
        } else {
            WITHOUT_NOT_BEFORE_OFFSET
        });
        let minimum_permission_domain_length =
            permission_domain_count(encoded) as u16 * (2 + 16 + 1); // domain length + key length + 1 byte payload
        let expected_length = offset + minimum_permission_domain_length + SIGNATURE_LENGTH_V0;
        if (encoded.len() as u16) < expected_length {
            return Err(CodecError::BadEncoding(&"Too short"));
        }

        Ok(DoughnutV0(encoded))
    }

    /// Returns the doughnut payload version
    pub fn payload_version(&self) -> u16 {
        payload_version(self.0)
    }

    /// Returns the doughnut "permission domain count"
    pub fn permission_domain_count(&self) -> u8 {
        permission_domain_count(self.0)
    }

    /// Whether the doughnut has "not before" bit set
    fn has_not_before(&self) -> bool {
        has_not_before(self.0)
    }
}

impl<'a> Encode for DoughnutV0<'a> {
    /// Convert self to an owned vector.
    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::{DoughnutV0 as Doughnut, ValidationError};
    use crate::traits::DoughnutApi;
    use crate::v0::parity::DoughnutV0;
    use parity_codec::Encode;
    use primitive_types::H256;
    use std::ops::Add;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // Make a unix timestamp `when` seconds from the invocation
    fn make_unix_timestamp(when: u64) -> u32 {
        SystemTime::now()
            .add(Duration::from_secs(when))
            .duration_since(UNIX_EPOCH)
            .expect("it works")
            .as_millis() as u32
    }

    #[test]
    fn it_is_a_valid_usage() {
        let holder = H256::from([1u8; 32]);
        // NOTE: We use parity version to create the test doughnut since this module's version is just a bytes window
        let _doughnut = DoughnutV0 {
            issuer: H256::from([0u8; 32]),
            holder,
            domains: vec![("test".to_string(), vec![0])],
            expiry: make_unix_timestamp(10),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: Default::default(), // No need to check signature here
        };
        let encoded = _doughnut.encode();
        let doughnut = Doughnut::new(&encoded).unwrap();

        assert!(doughnut
            .validate(&holder.into(), make_unix_timestamp(0))
            .is_ok())
    }
    #[test]
    fn usage_after_expiry_is_invalid() {
        let holder = H256::from([1u8; 32]);
        let _doughnut = DoughnutV0 {
            issuer: H256::from([0u8; 32]),
            holder,
            domains: vec![("test".to_string(), vec![0])],
            expiry: make_unix_timestamp(0),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: Default::default(), // No need to check signature here
        };
        let encoded = _doughnut.encode();
        let doughnut = Doughnut::new(&encoded).unwrap();

        assert_eq!(
            doughnut.validate(&holder.into(), make_unix_timestamp(5)),
            Err(ValidationError::Expired)
        )
    }
    #[test]
    fn usage_by_non_holder_is_invalid() {
        let holder = H256::from([1u8; 32]);
        let _doughnut = DoughnutV0 {
            issuer: H256::from([0u8; 32]),
            holder,
            domains: vec![("test".to_string(), vec![0])],
            expiry: make_unix_timestamp(10),
            not_before: 0,
            payload_version: 0,
            signature_version: 0,
            signature: Default::default(), // No need to check signature here
        };
        let encoded = _doughnut.encode();
        let doughnut = Doughnut::new(&encoded).unwrap();

        let not_the_holder = H256::from([2u8; 32]);
        assert_eq!(
            doughnut.validate(&not_the_holder.into(), make_unix_timestamp(0)),
            Err(ValidationError::HolderIdentityMismatched)
        )
    }
    #[test]
    fn usage_preceeding_not_before_is_invalid() {
        let holder = H256::from([1u8; 32]);
        let _doughnut = DoughnutV0 {
            issuer: H256::from([0u8; 32]),
            holder,
            domains: vec![("test".to_string(), vec![0])],
            expiry: make_unix_timestamp(12),
            not_before: make_unix_timestamp(10),
            payload_version: 0,
            signature_version: 0,
            signature: Default::default(), // No need to check signature here
        };
        let encoded = _doughnut.encode();
        let doughnut = Doughnut::new(&encoded).unwrap();

        assert_eq!(
            doughnut.validate(&holder.into(), make_unix_timestamp(0)),
            Err(ValidationError::Premature)
        )
    }
}
