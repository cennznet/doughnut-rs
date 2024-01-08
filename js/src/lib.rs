// Copyright 2022-2023 Futureverse Corporation Limited

//! Provide JS-Rust API bindings to create and inspect Doughnuts

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::{format, string::ToString, vec::Vec};
use codec::{Decode, Encode};
use core::convert::TryInto;
use doughnut_rs::{
    doughnut::{Doughnut, DoughnutV0, DoughnutV1},
    traits::{DoughnutApi, DoughnutVerify, PayloadVersion, Signing},
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

#[inline]
fn from_slice_33(bytes: &[u8]) -> [u8; 33] {
    let mut array = [0; 33];
    if bytes.len() < 33 {
        log("expected 33 byte array");
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
    /// Create a new Doughnut
    pub fn new(
        doughnut_version: u16,
        issuer: &[u8],
        holder: &[u8],
        fee_mode: u8,
        expiry: u32,
        not_before: u32,
    ) -> Self {
        match doughnut_version
            .try_into()
            .expect("Unsupported doughnut version")
        {
            PayloadVersion::V0 => {
                let mut doughnut = DoughnutV0::default();
                doughnut.payload_version = PayloadVersion::V0 as u16;
                doughnut.issuer = from_slice_32(issuer);
                doughnut.holder = from_slice_32(holder);
                doughnut.not_before = not_before;
                doughnut.expiry = expiry;

                JsHandle(Doughnut::V0(doughnut))
            }
            PayloadVersion::V1 => {
                let mut doughnut = DoughnutV1::default();
                doughnut.payload_version = PayloadVersion::V1 as u16;
                doughnut.issuer = from_slice_33(issuer);
                doughnut.holder = from_slice_33(holder);
                doughnut.fee_mode = fee_mode.try_into().expect("Unsupported fee mode");
                doughnut.not_before = not_before;
                doughnut.expiry = expiry;

                JsHandle(Doughnut::V1(doughnut))
            }
        }
    }

    #[allow(non_snake_case)]
    /// Add a permission domain to this `doughnut`
    pub fn addDomain(&mut self, key: &str, value: &[u8]) -> Self {
        match self.0 {
            Doughnut::V0(ref mut doughnut) => {
                doughnut.domains.push((key.to_string(), value.to_vec()));
                return self.clone();
            }
            Doughnut::V1(ref mut doughnut) => {
                doughnut.domains.push((key.to_string(), value.to_vec()));
                return self.clone();
            }
        }
    }

    #[allow(non_snake_case)]
    /// Sign and return ed25519 signature
    pub fn signSr25519(&mut self, secret_key: &[u8]) -> Result<JsHandle, JsValue> {
        // only PayloadVersion::V0 supports Sr25519
        if self.payloadVersion() != PayloadVersion::V0 as u16 {
            panic!("unsupported doughnut version and signing scheme");
        }

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
        // only PayloadVersion::V0 supports Ed25519
        if self.payloadVersion() != PayloadVersion::V0 as u16 {
            panic!("unsupported doughnut version and signing scheme");
        }

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

    #[allow(non_snake_case)]
    /// Sign and return ECDSA signature
    pub fn signECDSA(&mut self, secret_key: &[u8]) -> Result<JsHandle, JsValue> {
        // only PayloadVersion::V1 supports ECDSA
        if self.payloadVersion() != PayloadVersion::V1 as u16 {
            panic!("unsupported doughnut version and signing scheme");
        }

        let secret_key: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| JsValue::from_str("invalid secret key"))?;
        if let Doughnut::V1(ref mut doughnut) = &mut self.0 {
            let _signature = doughnut
                .sign_ecdsa(&secret_key)
                .map(|_| ())
                // throws: 'undefined' in JS on error
                .map_err(|_| JsValue::undefined())?;
            return Ok(self.clone());
        }
        panic!("unsupported doughnut version");
    }

    /// Return the doughnut issuer
    pub fn issuer(&self) -> Vec<u8> {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.issuer().to_vec();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.issuer().to_vec();
            }
        }
    }

    /// Return the doughnut holder
    pub fn holder(&self) -> Vec<u8> {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.holder().to_vec();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.holder().to_vec();
            }
        }
    }

    /// Return the doughnut expiry timestamp
    pub fn expiry(&self) -> u32 {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.expiry();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.expiry();
            }
        }
    }

    #[allow(non_snake_case)]
    /// Return the doughnut 'not before' timestamp
    pub fn notBefore(&self) -> u32 {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.not_before();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.not_before();
            }
        }
    }

    /// Return the doughnut payload bytes
    pub fn payload(&self) -> Vec<u8> {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.payload();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.payload();
            }
        }
    }

    /// Return the doughnut signature
    pub fn signature(&self) -> Vec<u8> {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.signature().to_vec();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.signature().to_vec();
            }
        }
    }

    #[allow(non_snake_case)]
    /// Return the doughnut signature version
    pub fn signatureVersion(&self) -> u8 {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.signature_version();
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.signature_version();
            }
        }
    }

    #[allow(non_snake_case)]
    /// Return the doughnut payload version
    pub fn payloadVersion(&self) -> u16 {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut.payload_version;
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut.payload_version;
            }
        }
    }

    /// Return the payload for domain, if it exists in the doughnut
    /// This will throw "undefined" in JS if the domain is not found
    pub fn domain(&self, domain: &str) -> Result<Vec<u8>, JsValue> {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                return doughnut
                    .get_domain(domain)
                    .map(|d| Ok(d.to_vec()))
                    .unwrap_or_else(|| Err(JsValue::undefined()))
            }
            Doughnut::V1(ref doughnut) => {
                return doughnut
                    .get_domain(domain)
                    .map(|d| Ok(d.to_vec()))
                    .unwrap_or_else(|| Err(JsValue::undefined()))
            }
        }
    }

    /// Verify the doughnut is:
    /// 1) issued to a public key (`who`)
    /// 2) usable at the current timestamp (`not_before` <= `now` <= `expiry`)
    /// 3) is correctly signed by the issuer
    pub fn verify(&self, who: &[u8], when: u32) -> bool {
        match self.0 {
            Doughnut::V0(ref doughnut) => {
                // TODO: Return errors
                return doughnut.validate(who, when).is_ok() && doughnut.verify().is_ok();
            }
            Doughnut::V1(ref doughnut) => {
                // TODO: Return errors
                return doughnut.validate(who, when).is_ok() && doughnut.verify().is_ok();
            }
        }
    }

    /// Encode the doughnut into bytes
    pub fn encode(&mut self) -> Vec<u8> {
        self.0.encode()
    }

    /// Decode a doughnut from `input` bytes
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
