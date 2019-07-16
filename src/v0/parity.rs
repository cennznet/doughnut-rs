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
//! This version is for interoperability within the substrate extrinsic environment.
//! It uses the `parity_codec` crate to consume a contiguous stream of bytes, without any look-ahead.
//! It however, does not use the SCALE codec.
//!
use bit_reverse::ParallelReverse;
use core::iter::IntoIterator;
use parity_codec::{Decode, Encode, Input, Output};
use primitive_types::{H256, H512};

use crate::alloc::string::{String, ToString};
use crate::alloc::vec::Vec;
use crate::traits::DoughnutApi;

const NOT_BEFORE_MASK: u8 = 0b1000_0000;
const SIGNATURE_MASK: u8 = 0b0001_1111;

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct DoughnutV0 {
    pub issuer: H256,
    pub holder: H256,
    pub domains: Vec<(String, Vec<u8>)>,
    pub expiry: u32,
    pub not_before: u32,
    pub payload_version: u16,
    pub signature_version: u8,
    pub signature: H512,
}

/// A 512-bit signature type
/// It wraps `[u8; 64]` with some useful conversion traits for Shim targeted at substrate.
pub struct Signature([u8; 64]);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DoughnutApi for DoughnutV0 {
    type AccountId = H256;
    type Timestamp = u32;
    type Signature = Signature;
    /// Return the doughnut holder account ID
    fn holder(&self) -> Self::AccountId {
        self.holder
    }
    /// Return the doughnut issuer account ID
    fn issuer(&self) -> Self::AccountId {
        self.issuer
    }
    /// Return the doughnut expiry timestamp
    fn expiry(&self) -> Self::Timestamp {
        self.expiry
    }
    /// Return the doughnut payload bytes
    fn payload(&self) -> Vec<u8> {
        let buf = self.encode();
        // TODO: Fix this. We encode signature bytes and then discard them
        buf[..buf.len() - 64].to_vec()
    }
    /// Return the doughnut signature bytes
    fn signature(&self) -> Self::Signature {
        Signature(self.signature.into())
    }
    /// Return the doughnut signature version
    fn signature_version(&self) -> u8 {
        self.signature_version
    }
    /// Return the payload by `domain` key, if it exists in this doughnut
    fn get_domain(&self, domain: &str) -> Option<&[u8]> {
        for (key, payload) in self.domains.iter() {
            if key == domain {
                return Some(&payload);
            }
        }
        None
    }
}

impl Decode for DoughnutV0 {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let payload_byte_0 = input.read_byte()?.swap_bits();
        let payload_byte_1 = input.read_byte()?.swap_bits();

        let payload_version = u16::from_le_bytes([payload_byte_0, payload_byte_1 & 0b1110_0000]);

        let signature_version = (payload_byte_1 & SIGNATURE_MASK) >> 3;

        let domain_count_and_not_before_byte = input.read_byte()?;
        let permission_domain_count = (domain_count_and_not_before_byte << 1).swap_bits() + 1;
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
        let mut domains: Vec<(String, Vec<u8>)> = Default::default();
        // A queue for domain keys and lengths from the domains header section
        // We use this to order later reads from the domain payload section since we
        // are restricted by `input` to read the payload byte-by-byte
        let mut q: Vec<(String, usize)> = Default::default();

        for _ in 0..permission_domain_count {
            let mut key_buf: [u8; 16] = Default::default();
            let _ = input.read(&mut key_buf);
            let key = core::str::from_utf8(&key_buf)
                .ok()?
                .trim_matches(char::from(0))
                .to_string();

            let payload_length = u16::from_le_bytes([
                input.read_byte()?.swap_bits(),
                input.read_byte()?.swap_bits(),
            ]);
            q.push((key, payload_length as usize));
        }

        for (key, payload_length) in q.into_iter() {
            let mut payload = Vec::with_capacity(payload_length);
            unsafe {
                payload.set_len(payload_length);
            }
            let _ = input.read(&mut payload);
            domains.push((key, payload));
        }

        let mut signature = [0u8; 64];
        let _ = input.read(&mut signature);

        Some(DoughnutV0 {
            holder: H256::from(holder),
            issuer: H256::from(issuer),
            expiry,
            not_before,
            signature_version,
            payload_version,
            domains,
            signature: H512::from(signature),
        })
    }
}

impl Encode for DoughnutV0 {
    fn encode_to<T: Output>(&self, dest: &mut T) {
        let mut payload_version_and_signature_version = self.payload_version.swap_bits();
        payload_version_and_signature_version |= ((self.signature_version as u16) << 3).swap_bits();
        dest.write(&payload_version_and_signature_version.to_le_bytes());

        let mut domain_count_and_not_before_byte = ((self.domains.len() as u8) - 1) << 1;
        if self.not_before > 0 {
            domain_count_and_not_before_byte |= NOT_BEFORE_MASK
        }
        dest.push_byte(domain_count_and_not_before_byte.swap_bits());
        dest.write(self.issuer.as_bytes());
        dest.write(self.holder.as_bytes());

        for b in self.expiry.to_le_bytes().into_iter() {
            dest.push_byte(b.swap_bits());
        }

        if self.not_before > 0 {
            for b in self.not_before.to_le_bytes().into_iter() {
                dest.push_byte(b.swap_bits());
            }
        }

        // Write permission domain headers
        for (key, payload) in self.domains.iter() {
            let mut key_buf = [0u8; 16];
            for i in 0..key.len() {
                key_buf[i] = key.as_bytes()[i];
            }
            dest.write(&key_buf);
            for b in (payload.len() as u16).to_le_bytes().iter() {
                dest.push_byte(b.swap_bits());
            }
        }

        // Write permission domain payloads
        for (_, payload) in self.domains.iter() {
            dest.write(payload);
        }

        dest.write(self.signature.as_bytes());
    }
}
