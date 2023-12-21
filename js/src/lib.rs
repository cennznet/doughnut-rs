// Copyright 2022-2023 Futureverse Corporation Limited

//! Provide JS-Rust API bindings to create and inspect Doughnuts

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::vec::Vec;
use alloc::format;
use alloc::string::ToString;

use codec::{Decode, Encode};
use doughnut_rs::{
    traits::{DoughnutApi, DoughnutVerify, Signing},
    doughnut::{Doughnut, DoughnutV0},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[inline]
fn from_slice_32(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    if bytes.len() < 32 {
        log("expected 32 byte array");
        return array;
    }
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

/// A js handle for a rust versioned doughnut struct
#[wasm_bindgen(js_name = Doughnut)]
#[derive(Clone)]
pub struct JsHandle(Doughnut);

#[wasm_bindgen(js_class = Doughnut)]
#[allow(irrefutable_let_patterns)]
impl JsHandle {
    #[wasm_bindgen(constructor)]
    /// Create a new Doughnut, it is always v0 for now
    pub fn new(issuer: &[u8], holder: &[u8], expiry: u32, not_before: u32) -> Self {
        let mut doughnut = DoughnutV0::default();
        doughnut.payload_version = 0;
        doughnut.issuer = from_slice_32(issuer);
        doughnut.holder = from_slice_32(holder);
        doughnut.not_before = not_before;
        doughnut.expiry = expiry;

        JsHandle(Doughnut::V0(doughnut))
    }

    #[allow(non_snake_case)]
    /// Add a permission domain to this `doughnut`
    pub fn addDomain(&mut self, key: &str, value: &[u8]) -> Self {
        if let Doughnut::V0(ref mut doughnut) = &mut self.0 {
            doughnut.domains.push((key.to_string(), value.to_vec()));
            return self.clone();
        }
        panic!("unsupported doughnut version");
    }

    #[allow(non_snake_case)]
    /// Sign and return ed25519 signature
    pub fn signSr25519(&mut self, secret_key: &[u8]) -> Result<JsHandle, JsValue> {
        let secret_key: [u8; 64] = secret_key
            .try_into()
            .map_err(|_| JsValue::from_str("invalid secret key"))?;
        if let Doughnut::V0(ref mut doughnut) = &mut self.0 {
            let _signature = doughnut
                .sign_sr25519(&secret_key)
                .map(|_| ())
                // throws: 'undefined' in JS on error
                .map_err(|_| JsValue::undefined())?;
            return Ok(self.clone());
        }
        panic!("unsupported doughnut version");
    }

    #[allow(non_snake_case)]
    /// Sign and return ed25519 signature
    pub fn signEd25519(&mut self, secret_key: &[u8]) -> Result<JsHandle, JsValue> {
        let secret_key: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| JsValue::from_str("invalid secret key"))?;
        if let Doughnut::V0(ref mut doughnut) = &mut self.0 {
            let _signature = doughnut
                .sign_ed25519(&secret_key)
                .map(|_| ())
                // throws: 'undefined' in JS on error
                .map_err(|_| JsValue::undefined())?;
            return Ok(self.clone());
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut issuer
    pub fn issuer(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.issuer().to_vec();
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut holder
    pub fn holder(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.holder().to_vec();
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut expiry timestamp
    pub fn expiry(&self) -> u32 {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.expiry();
        }
        panic!("unsupported doughnut version");
    }

    #[allow(non_snake_case)]
    /// Return the doughnut 'not before' timestamp
    pub fn notBefore(&self) -> u32 {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.not_before();
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut payload bytes
    pub fn payload(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.payload();
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut signature
    pub fn signature(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.signature().to_vec();
        }
        panic!("unsupported doughnut version");
    }

    #[allow(non_snake_case)]
    /// Return the doughnut signature version
    pub fn signatureVersion(&self) -> u8 {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.signature_version();
        }
        panic!("unsupported doughnut version");
    }

    #[allow(non_snake_case)]
    /// Return the doughnut payload version
    pub fn payloadVersion(&self) -> u16 {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut.payload_version;
        }
        panic!("unsupported doughnut version");
    }

    /// Return the payload for domain, if it exists in the doughnut
    /// This will throw "undefined" in JS if the domain is not found
    pub fn domain(&self, domain: &str) -> Result<Vec<u8>, JsValue> {
        if let Doughnut::V0(doughnut) = &self.0 {
            return doughnut
                .get_domain(domain)
                .map(|d| Ok(d.to_vec()))
                .unwrap_or_else(|| Err(JsValue::undefined()))
        }
        panic!("unsupported doughnut version");
    }

    /// Verify the doughnut is:
    /// 1) issued to a public key (`who`)
    /// 2) usable at the current timestamp (`not_before` <= `now` <= `expiry`)
    /// 3) is correctly signed by the issuer
    pub fn verify(&self, who: &[u8], when: u32) -> bool {
        if let Doughnut::V0(doughnut) = &self.0 {
            // TODO: Return errors
            return doughnut.validate(who, when).is_ok() && doughnut.verify().is_ok();
        }
        panic!("unsupported doughnut version");
    }

    /// Encode the doughnut into bytes
    pub fn encode(&mut self) -> Vec<u8> {
        self.0.encode()
    }

    /// Decode a version 0 doughnut from `input` bytes
    pub fn decode(input: &[u8]) -> Result<JsHandle, JsValue> {
        match Doughnut::decode(&mut &input[..]) {
            Ok(doughnut) => Ok(JsHandle(doughnut)),
            Err(err) => {
                log(&format!("failed decoding: {:?}", err));
                Err(JsValue::undefined())
            }
        }
    }
}
