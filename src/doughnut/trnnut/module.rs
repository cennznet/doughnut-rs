// Copyright 2022-2023 Futureverse Corporation Limited
//!
//! # TRNNut - Module
//!
//! Delegated runtime module permissions of TRNNut for use in TRN
//!

use super::method::Method;
use super::WILDCARD;
use crate::doughnut::trnnut::trnnut::MAX_METHODS;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use codec::{Decode, Encode, Input, Output};
use core::convert::TryFrom;

const BLOCK_COOLDOWN_MASK: u8 = 0b0000_0001;

/// A TRN permission domain module
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Module {
    pub name: String,
    pub block_cooldown: Option<u32>,
    pub methods: Vec<Method>,
}

impl Module {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            block_cooldown: None,
            methods: Vec::new(),
        }
    }

    pub fn block_cooldown(mut self, block_cooldown: u32) -> Self {
        self.block_cooldown = Some(block_cooldown);
        self
    }

    pub fn methods(mut self, methods: Vec<Method>) -> Self {
        self.methods = methods;
        self
    }

    /// Returns the method, if it exists in the Module
    /// Wildcard methods have lower priority than defined methods
    pub fn get_method(&self, method: &str) -> Option<&Method> {
        let mut outcome: Option<&Method> = None;
        for m in &self.methods {
            if m.name == method {
                outcome = Some(m);
                break;
            } else if m.name == WILDCARD {
                outcome = Some(m);
            }
        }
        outcome
    }
}

impl Encode for Module {
    fn encode_to<T: Output + ?Sized>(&self, buf: &mut T) {
        if self.methods.is_empty() || self.methods.len() > MAX_METHODS {
            return;
        }
        let method_count = u8::try_from(self.methods.len() - 1);
        if method_count.is_err() {
            return;
        }
        let mut method_count_and_has_cooldown_byte = method_count.unwrap() << 1;
        if self.block_cooldown.is_some() {
            method_count_and_has_cooldown_byte |= BLOCK_COOLDOWN_MASK;
        }
        buf.push_byte(method_count_and_has_cooldown_byte);

        let mut name = [0_u8; 32];
        let length = 32.min(self.name.len());
        name[0..length].clone_from_slice(&self.name.as_bytes()[0..length]);

        buf.write(&name);

        if let Some(cooldown) = self.block_cooldown {
            for b in &cooldown.to_le_bytes() {
                buf.push_byte(*b);
            }
        }

        for method in &self.methods {
            method.encode_to(buf);
        }
    }
}

impl Decode for Module {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let block_cooldown_and_method_count: u8 = input.read_byte()?;
        let method_count = (block_cooldown_and_method_count >> 1) + 1;

        let mut name_buf: [u8; 32] = Default::default();
        input
            .read(&mut name_buf)
            .map_err(|_| "expected 32 byte module name")?;
        let name = core::str::from_utf8(&name_buf)
            .map_err(|_| codec::Error::from("module names should be utf8 encoded"))?
            .trim_matches(char::from(0))
            .to_string();

        let module_cooldown =
            if (block_cooldown_and_method_count & BLOCK_COOLDOWN_MASK) == BLOCK_COOLDOWN_MASK {
                Some(u32::from_le_bytes([
                    input.read_byte()?,
                    input.read_byte()?,
                    input.read_byte()?,
                    input.read_byte()?,
                ]))
            } else {
                None
            };

        let mut methods: Vec<Method> = Vec::default();

        for _ in 0..method_count {
            let m: Method = Decode::decode(input)?;
            methods.push(m);
        }

        Ok(Self {
            name,
            block_cooldown: module_cooldown,
            methods,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Method, Module, BLOCK_COOLDOWN_MASK};
    use codec::{Decode, Encode};
    use std::assert_eq;

    macro_rules! methods {
        ($($name:expr),*) => {
            vec![
                $( ( Method::new($name) ), )*
            ]
        }
    }

    // Constructor tests
    #[test]
    fn it_initializes() {
        let module = Module::new("TestModule");

        assert_eq!(module.name, "TestModule");
        assert_eq!(module.block_cooldown, None);
        assert_eq!(module.methods, vec![]);
    }

    // Encoding Tests
    #[test]
    fn it_encodes() {
        let module = Module::new("TestModule").methods(methods!("TestMethod"));

        let expected_name = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![0_u8],
            expected_name,
            remainder,
            Method::new("TestMethod").encode(),
        ]
        .concat();

        assert_eq!(module.encode(), expected);
    }

    #[test]
    fn it_does_not_encode_without_methods() {
        let module = Module::new("TestModule");
        assert_eq!(module.encode(), Vec::<u8>::default());
    }

    #[test]
    fn it_encodes_only_32_characters_for_name() {
        let module = Module::new("I don't like green eggs and ham, I don't like you Sam I am;")
            .methods(methods!("TestMethod"));
        let expected_length = 33 + 33;

        assert_eq!(module.encode().len(), expected_length);
    }

    #[test]
    fn it_encodes_with_block_cooldown() {
        let module = Module::new("TestModule")
            .methods(methods!("TestMethod"))
            .block_cooldown(0x10204080);

        let expected_name = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            expected_name,
            remainder,
            vec![0x80, 0x40, 0x20, 0x10],
            Method::new("TestMethod").encode(),
        ]
        .concat();

        assert_eq!(module.encode(), expected);
    }

    #[test]
    fn it_encodes_with_many_methods() {
        let module = Module::new("TestModule")
            .methods(methods!("I", "do", "not", "like", "them", "Sam", "I am"));

        let expected_name = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - expected_name.len()];
        let expected: Vec<u8> = [
            vec![0x06_u8 << 1], // 6 + 1 methods
            expected_name,
            remainder,
            Method::new("I").encode(),
            Method::new("do").encode(),
            Method::new("not").encode(),
            Method::new("like").encode(),
            Method::new("them").encode(),
            Method::new("Sam").encode(),
            Method::new("I am").encode(),
        ]
        .concat();

        assert_eq!(module.encode(), expected);
    }

    // Decoding Tests
    #[test]
    fn it_decodes() {
        let name_bytes = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![0_u8],
            name_bytes,
            remainder,
            Method::new("TestMethod").encode(),
        ]
        .concat();

        let module = Module::decode(&mut &encoded[..]).unwrap();
        assert_eq!(module.name, "TestModule");
        assert_eq!(module.block_cooldown, None);
        assert_eq!(module.methods.len(), 1);
    }

    #[test]
    fn decode_fails_with_junk_bytes_in_the_name() {
        let name_bytes = String::from("TestModule").into_bytes();
        let remainder = vec![0xf0_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![0_u8],
            name_bytes,
            remainder,
            Method::new("TestMethod").encode(),
        ]
        .concat();

        assert_eq!(
            Module::decode(&mut &encoded[..]),
            Err(codec::Error::from("module names should be utf8 encoded"))
        );
    }

    #[test]
    fn it_decodes_with_block_cooldown() {
        let name_bytes = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            name_bytes,
            remainder,
            vec![0x80, 0x40, 0x20, 0x10],
            Method::new("TestMethod").encode(),
        ]
        .concat();

        let module = Module::decode(&mut &encoded[..]).unwrap();
        assert_eq!(module.name, "TestModule");
        assert_eq!(module.block_cooldown, Some(0x10204080));
        assert_eq!(module.methods.len(), 1);
    }

    #[test]
    fn decode_fails_with_insufficient_bytes_for_block_cooldown() {
        let name_bytes = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![BLOCK_COOLDOWN_MASK],
            name_bytes,
            remainder,
            vec![0x01, 0x02],
            Method::new("TestMethod").encode(),
        ]
        .concat();

        assert_eq!(
            Module::decode(&mut &encoded[..]),
            Err(codec::Error::from("expected 32 byte method name"))
        );
    }

    #[test]
    fn it_decodes_with_many_methods() {
        let name_bytes = String::from("TestModule").into_bytes();
        let remainder = vec![0x00_u8; 32_usize - name_bytes.len()];
        let encoded: Vec<u8> = [
            vec![0x06_u8 << 1], // 6 + 1 methods
            name_bytes,
            remainder,
            Method::new("I").encode(),
            Method::new("do").encode(),
            Method::new("not").encode(),
            Method::new("like").encode(),
            Method::new("them").encode(),
            Method::new("Sam").encode(),
            Method::new("I am").encode(),
        ]
        .concat();

        let module = Module::decode(&mut &encoded[..]).unwrap();

        assert_eq!(module.methods[0].name, "I");
        assert_eq!(module.methods[1].name, "do");
        assert_eq!(module.methods[2].name, "not");
        assert_eq!(module.methods[3].name, "like");
        assert_eq!(module.methods[4].name, "them");
        assert_eq!(module.methods[5].name, "Sam");
        assert_eq!(module.methods[6].name, "I am");
    }
}
