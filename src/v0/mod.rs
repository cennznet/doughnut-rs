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
use crate::error::DoughnutErr;
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
    type AccountId = [u8; 32];
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

    /// Returns the doughnut holder public key
    fn holder(&self) -> Self::AccountId {
        let offset = 35;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const Self::AccountId) }
    }

    /// Returns the doughnut issuer public key
    fn issuer(&self) -> Self::AccountId {
        let offset = 3;
        unsafe { ptr::read(self.0[offset..offset + 32].as_ptr() as *const Self::AccountId) }
    }

    ///Returns the doughnut payload (no signature)
    fn payload(&self) -> Vec<u8> {
        self.0[..self.0.len() - 64].to_vec()
    }

    // Returns the doughnut signature
    fn signature(&self) -> Self::Signature {
        unsafe { ptr::read(self.0[(self.0.len() - 64)..].as_ptr() as *const [u8; 64]) }
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
        let mut domain_offset = u16::from(offset) + u16::from(self.permission_domain_count() * 18);
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
}

/// Return the payload version from the given byte slice
fn payload_version(buf: &[u8]) -> u16 {
    let payload_version = u16::from_le_bytes([buf[0].swap_bits(), buf[1].swap_bits()]);
    payload_version & VERSION_MASK
}

/// Returns the doughnut "permission domain count"
fn permission_domain_count(buf: &[u8]) -> u8 {
    (buf[2] << 1).swap_bits() + 1
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
    pub fn new(encoded: &'a [u8]) -> Result<Self, DoughnutErr<'a>> {
        if encoded.len() < 2 {
            return Err(DoughnutErr::BadEncoding(&"Missing header"));
        }
        if payload_version(encoded) != VERSION {
            return Err(DoughnutErr::UnsupportedVersion);
        }

        let offset = u16::from(if has_not_before(encoded) {
            WITH_NOT_BEFORE_OFFSET
        } else {
            WITHOUT_NOT_BEFORE_OFFSET
        });
        let minimum_permission_domain_length = permission_domain_count(encoded) as u16 * (18 + 1); // + 1 byte per domain expected in payload
        let expected_length = offset + minimum_permission_domain_length + SIGNATURE_LENGTH_V0;
        if (encoded.len() as u16) < expected_length {
            return Err(DoughnutErr::BadEncoding(&"Too short"));
        }

        Ok(DoughnutV0(encoded))
    }

    /// Returns the doughnut payload version
    pub fn payload_version(&self) -> u16 {
        payload_version(self.0)
    }

    /// Returns the doughnut signature scheme version
    pub fn signature_version(&self) -> u8 {
        self.0[1].swap_bits() & SIGNATURE_MASK
    }

    /// Returns the doughnut "permission domain count"
    pub fn permission_domain_count(&self) -> u8 {
        permission_domain_count(self.0)
    }

    /// Whether the doughnut has "not before" bit set
    fn has_not_before(&self) -> bool {
        has_not_before(self.0)
    }

    /// Returns the doughnut "not before" unix timestamp
    pub fn not_before(&self) -> u32 {
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
}

impl<'a> Encode for DoughnutV0<'a> {
    /// Convert self to an owned vector.
    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
