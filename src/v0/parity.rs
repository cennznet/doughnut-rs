//!
//! Doughnut V0 codec (parity)
//!
use bit_reverse::ParallelReverse;
use core::iter::IntoIterator;
use hashbrown::HashMap;
use parity_codec::{Decode, Encode, Input};
use primitive_types::H512;

use crate::alloc::string::{String, ToString};
use crate::alloc::vec::Vec;

const NOT_BEFORE_MASK: u8 = 0b1000_0000;
const SIGNATURE_MASK: u8 = 0b0001_1111;

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct DoughnutV0 {
    pub issuer: [u8; 32],
    pub holder: [u8; 32],
    pub expiry: u32,
    pub not_before: u32,
    pub payload_version: u16,
    pub signature_version: u8,
    pub domains: HashMap<String, Vec<u8>>,
    pub signature: H512,
    domain_index: Vec<(String, usize)>, // Maintains order of domain headers/payloads
}

impl Decode for DoughnutV0 {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let payload_byte_0 = input.read_byte()?.swap_bits();
        let payload_byte_1 = input.read_byte()?.swap_bits();

        let payload_version = u16::from_le_bytes([payload_byte_0, payload_byte_1 & 0b1110_0000]);

        let signature_version = payload_byte_1 & SIGNATURE_MASK;

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

        // Build permissions/domains map
        let mut domains: HashMap<String, Vec<u8>> = HashMap::new();
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

        for (key, payload_length) in q.iter() {
            let mut payload = Vec::with_capacity(*payload_length);
            unsafe {
                payload.set_len(*payload_length);
            }
            let _ = input.read(&mut payload);
            domains.insert(key.clone(), payload);
        }

        let mut signature = [0u8; 64];
        let _ = input.read(&mut signature);

        Some(DoughnutV0 {
            holder,
            issuer,
            expiry,
            not_before,
            signature_version,
            payload_version,
            domains,
            signature: H512::from(signature),
            domain_index: q,
        })
    }
}

impl Encode for DoughnutV0 {
    fn encode(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Default::default();

        let mut payload_version_and_signature_version = self.payload_version.swap_bits();
        payload_version_and_signature_version |= (self.signature_version.swap_bits() as u16) << 8;
        buf.extend(&payload_version_and_signature_version.to_le_bytes());

        let mut domain_count_and_not_before_byte = self.domains.len() as u8;
        if self.not_before > 0 {
            domain_count_and_not_before_byte |= NOT_BEFORE_MASK
        }
        buf.push(domain_count_and_not_before_byte.swap_bits());
        buf.extend(&self.issuer);
        buf.extend(&self.holder);

        for b in self.expiry.to_le_bytes().into_iter() {
            buf.push(b.swap_bits());
        }

        if self.not_before > 0 {
            for b in self.not_before.to_le_bytes().into_iter() {
                buf.push(b.swap_bits());
            }
        }

        // We don't use `self.domains` as insertion order is not guaranteed
        for (key, payload_len) in self.domain_index.iter() {
            let mut key_buf = [0u8; 16];
            for i in 0..key.len() {
                key_buf[i] = key.as_bytes()[i];
            }
            buf.extend(&key_buf);
            for b in (*payload_len as u16).to_le_bytes().iter() {
                buf.push(b.swap_bits());
            }
        }

        for (key, _) in self.domain_index.iter() {
            let payload = self.domains.get(key).expect("It should be a valid key");
            buf.extend(payload);
        }

        buf.extend(self.signature.as_bytes());

        buf
    }
}
