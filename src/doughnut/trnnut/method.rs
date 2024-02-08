// Copyright 2022-2023 Futureverse Corporation Limited
//!
//! # TRNNut - Method
//!
//! Delegated method permissions of TRNNut for use in TRN
//!

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use codec::{Decode, Encode, Input, Output};
use core::convert::TryFrom;
use pact::types::Contract as PactContract;

const BLOCK_COOLDOWN_MASK: u8 = 0x01;
const CONSTRAINTS_MASK: u8 = 0x02;
const MAX_CONSTRAINTS: usize = 256;

/// A TRN permission domain module method
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Method {
    pub name: String,
    pub block_cooldown: Option<u32>,
    pub constraints: Option<Vec<u8>>,
}

impl Method {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            block_cooldown: None,
            constraints: None,
        }
    }

    pub fn block_cooldown(mut self, block_cooldown: u32) -> Self {
        self.block_cooldown = Some(block_cooldown);
        self
    }

    pub fn constraints(mut self, constraints: Vec<u8>) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Returns the Pact contract, if it exists in the Method
    pub fn get_pact(&self) -> Option<PactContract> {
        match &self.constraints {
            Some(constraints) => match PactContract::decode(constraints) {
                Ok(pact_contract) => Some(pact_contract),
                // This error case can only occur after initializing a Method with bad constraints.
                // A decoded Method will be checked during decoding.
                Err(_) => None,
            },
            None => None,
        }
    }
}

impl Encode for Method {
    fn encode_to<T: Output + ?Sized>(&self, buf: &mut T) {
        let has_cooldown_byte: u8 = if self.block_cooldown.is_some() {
            BLOCK_COOLDOWN_MASK
        } else {
            0
        };
        let has_constraints_byte: u8 = if let Some(constraints) = &self.constraints {
            if constraints.is_empty() {
                0
            } else {
                CONSTRAINTS_MASK
            }
        } else {
            0
        };
        buf.push_byte(has_cooldown_byte | has_constraints_byte);

        let mut name = [0_u8; 32];
        let length = 32.min(self.name.len());

        name[0..length].clone_from_slice(&self.name.as_bytes()[0..length]);

        buf.write(&name);

        if let Some(cooldown) = self.block_cooldown {
            for b in &cooldown.to_le_bytes() {
                buf.push_byte(*b);
            }
        }

        if let Some(constraints) = &self.constraints {
            let constraints_count =
                u8::try_from(MAX_CONSTRAINTS.min(constraints.len()).wrapping_sub(1));
            if let Ok(len_byte) = constraints_count {
                let len: usize = len_byte.into();
                buf.push_byte(len_byte);
                buf.write(&constraints[0..=len]);
            }
        }
    }
}

impl Decode for Method {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let block_cooldown_and_constraints = input.read_byte()?;

        let mut name_buf: [u8; 32] = Default::default();
        input
            .read(&mut name_buf)
            .map_err(|_| "expected 32 byte method name")?;
        let name = core::str::from_utf8(&name_buf)
            .map_err(|_| codec::Error::from("method names should be utf8 encoded"))?
            .trim_matches(char::from(0))
            .to_string();

        let block_cooldown: Option<u32> =
            if (block_cooldown_and_constraints & BLOCK_COOLDOWN_MASK) == BLOCK_COOLDOWN_MASK {
                Some(u32::from_le_bytes([
                    input.read_byte()?,
                    input.read_byte()?,
                    input.read_byte()?,
                    input.read_byte()?,
                ]))
            } else {
                None
            };

        let constraints: Option<Vec<u8>> =
            if (block_cooldown_and_constraints & CONSTRAINTS_MASK) == CONSTRAINTS_MASK {
                let constraints_length = (input.read_byte()?).saturating_add(1);
                let mut constraints_buf = Vec::<u8>::default();
                for _ in 0..constraints_length {
                    constraints_buf.push(input.read_byte()?);
                }
                if PactContract::decode(&constraints_buf).is_err() {
                    return Err(codec::Error::from("invalid constraints codec"));
                };
                Some(constraints_buf)
            } else {
                None
            };

        Ok(Self {
            name,
            block_cooldown,
            constraints,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Method, BLOCK_COOLDOWN_MASK, CONSTRAINTS_MASK};
    use codec::{Decode, Encode};
    use std::assert_eq;

    // Constructor tests
    #[test]
    fn it_initializes() {
        let method = Method::new("TestMethod");

        assert_eq!(method.name, "TestMethod");
        assert_eq!(method.block_cooldown, None);
        assert_eq!(method.constraints, None);
    }

    // Encoding Tests
    #[test]
    fn it_encodes() {
        let method = Method::new("TestMethod");

        let expected_name = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [vec![0_u8], expected_name, remainder].concat();

        assert_eq!(method.encode(), expected);
    }

    #[test]
    fn it_encodes_only_32_characters_for_name() {
        let method = Method::new("I am Sam, I am Sam, Sam I am; That Sam I am, That Sam I am, I do not like that Sam I am");
        let expected_length = 33;

        assert_eq!(method.encode().len(), expected_length);
    }

    #[test]
    fn it_encodes_with_block_cooldown() {
        let method = Method::new("TestMethod").block_cooldown(0x08040201);

        let expected_name = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            expected_name,
            remainder,
            vec![0x01, 0x02, 0x04, 0x08],
        ]
        .concat();

        assert_eq!(method.encode(), expected);
    }

    #[test]
    fn it_encodes_with_constraints() {
        let method = Method::new("TestMethod").constraints(vec![0x55; 9]);

        let expected_name = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![CONSTRAINTS_MASK],
            expected_name,
            remainder,
            vec![8],
            vec![0x55; 9],
        ]
        .concat();

        assert_eq!(method.encode(), expected);
    }

    #[test]
    fn bad_constraints_are_none() {
        let method = Method::new("TestMethod").constraints(vec![0x55; 9]);

        assert_eq!(method.get_pact(), None);
    }

    #[test]
    fn it_encodes_up_to_256_constraints_bytes() {
        let method = Method::new("TestMethod").constraints(vec![0x55; 300]);

        let expected_name = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![CONSTRAINTS_MASK],
            expected_name,
            remainder,
            vec![0xff],
            vec![0x55; 256],
        ]
        .concat();

        assert_eq!(method.encode(), expected);
    }

    #[test]
    fn it_does_not_encode_constraints_with_0_length() {
        let method = Method::new("TestMethod").constraints(vec![0x55; 0]);

        let expected_name = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [vec![0x00_u8], expected_name, remainder].concat();

        assert_eq!(method.encode(), expected);
    }

    // Decoding Tests
    #[test]
    fn it_decodes() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [vec![0_u8], name_bytes, remainder].concat();

        let method = Method::decode(&mut &encoded[..]).unwrap();
        assert_eq!(method.name, "TestMethod");
        assert_eq!(method.block_cooldown, None);
        assert_eq!(method.constraints, None);
    }

    #[test]
    fn decode_fails_with_junk_bytes_in_the_name() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0xf0_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [vec![0_u8], name_bytes, remainder].concat();

        assert_eq!(
            Method::decode(&mut &encoded[..]),
            Err(codec::Error::from("method names should be utf8 encoded"))
        );
    }

    #[test]
    fn it_decodes_with_block_cooldown() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            name_bytes,
            remainder,
            vec![0x01, 0x02, 0x04, 0x08],
        ]
        .concat();

        let method = Method::decode(&mut &encoded[..]).unwrap();
        assert_eq!(method.name, "TestMethod");
        assert_eq!(method.block_cooldown, Some(0x08040201));
        assert_eq!(method.constraints, None);
    }

    #[test]
    fn decode_fails_with_insufficient_bytes_for_block_cooldown() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            name_bytes,
            remainder,
            vec![0x01, 0x02, 0x04],
        ]
        .concat();

        assert_eq!(
            Method::decode(&mut &encoded[..]),
            Err(codec::Error::from("Not enough data to fill buffer"))
        );
    }

    #[test]
    fn it_decodes_with_pact() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let pact = vec![0x00; 33_usize];
        let encoded: Vec<u8> = [
            vec![CONSTRAINTS_MASK],
            name_bytes,
            remainder,
            vec![32],
            pact,
        ]
        .concat();

        let method = Method::decode(&mut &encoded[..]).unwrap();
        assert_eq!(method.name, "TestMethod");
        assert_eq!(method.block_cooldown, None);
        assert_eq!(method.constraints, Some(vec![0x00; 33]));
    }

    #[test]
    fn decode_fails_with_invalid_pact() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let pact = vec![0xff; 33_usize];
        let encoded: Vec<u8> = [
            vec![CONSTRAINTS_MASK],
            name_bytes,
            remainder,
            vec![32],
            pact,
        ]
        .concat();

        assert_eq!(
            Method::decode(&mut &encoded[..]),
            Err(codec::Error::from("invalid constraints codec"))
        );
    }

    #[test]
    fn decode_fails_with_insufficient_bytes_for_pact() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let pact = vec![0xff; 32_usize];
        let encoded: Vec<u8> = [
            vec![CONSTRAINTS_MASK],
            name_bytes,
            remainder,
            vec![32],
            pact,
        ]
        .concat();

        assert_eq!(
            Method::decode(&mut &encoded[..]),
            Err(codec::Error::from("Not enough data to fill buffer"))
        );
    }

    #[test]
    fn it_decodes_with_block_cooldown_and_pact() {
        let name_bytes = String::from("TestMethod").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let pact = vec![0x00; 33_usize];
        let encoded: Vec<u8> = [
            vec![CONSTRAINTS_MASK + BLOCK_COOLDOWN_MASK],
            name_bytes,
            remainder,
            vec![0x01, 0x02, 0x04, 0x08],
            vec![32],
            pact,
        ]
        .concat();

        let method = Method::decode(&mut &encoded[..]).unwrap();
        assert_eq!(method.name, "TestMethod");
        assert_eq!(method.block_cooldown, Some(0x08040201));
        assert_eq!(method.constraints, Some(vec![0x00; 33]));
    }
}
