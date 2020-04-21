// Copyright 2020 Centrality Investments Limited

// !
// ! Allow users to create, sign, and inspect doughnuts in JS
// ! Maybe use closures to pass in signer
// ! Builder-ish patter to make doughnuts

use wasm_bindgen::prelude::*;
use crate::doughnut::Doughnut;
use crate::v0::parity::DoughnutV0;
use crate::traits::{DoughnutApi, DoughnutVerify, SignDoughnut};
use codec::{Decode, Encode};
use primitive_types::H512;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[inline]
fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    if bytes.len() < 32 {
      log("operation failed, expected 32 byte array");
      return array;
    }
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes); 
    array
}

/// A js handle for a rust versioned doughnut struct
#[wasm_bindgen(constructor)]
#[derive(Clone, Encode)]
pub struct DoughnutHandle(Doughnut);

#[wasm_bindgen]
impl DoughnutHandle {
    /// Create a new Doughnut, it is always v0 for now
    pub fn new(issuer: &[u8], holder: &[u8], expiry: u32, not_before: u32) -> Self {
        let mut doughnut = DoughnutV0::default();
        doughnut.issuer = from_slice(issuer);
        doughnut.holder = from_slice(holder);
        doughnut.not_before = not_before;
        doughnut.expiry = expiry;

        DoughnutHandle(Doughnut::V0(doughnut))
    }

    /// Add payload version to this `doughnut`
    pub fn add_payload_version(&mut self, payload_version: u16) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            doughnut.payload_version = payload_version;
            return Self(Doughnut::V0(doughnut));
        } else {
            log("Setting payload version failed. Unsupported doughnut version");
        }
        self.clone()
    }

    /// Add domain to this `doughnut`
    pub fn add_domain(&mut self, key: &str, value: &[u8]) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            doughnut.domains.push((key.to_string(), value.to_vec()));
            return Self(Doughnut::V0(doughnut));
        } else {
            log("Adding domain failed. Unsupported doughnut version");
        }
        self.clone()
    }

    /// Add signature version to this `doughnut`
    pub fn add_signature_version(&mut self, signature_version: u8) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            doughnut.signature_version = signature_version;
            return Self(Doughnut::V0(doughnut));
        } else {
            log("Adding signature version failed. Unsupported doughnut version");
        }
        self.clone()
    }
    
    /// sign the doughnut payload
    pub fn sign(&mut self, secret_key: &[u8]) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            let signature = doughnut.sign(secret_key).unwrap();
            doughnut.signature = H512::from_slice(signature.as_ref());
            return Self(Doughnut::V0(doughnut));
        } else {
            log("Sign the doughnut payload failed. Unsupported doughnut version");
        }
        self.clone()
    }

    /// Return the doughnut issuer
    pub fn issuer(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.issuer().to_vec();
        } else {
            log("Getting issuer failed. Unsupported doughnut version");
        }
        Vec::<u8>::default()
    }

    /// Return the doughnut holder
    pub fn holder(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.holder().to_vec();
        } else {
            log("Getting holder failed. Unsupported doughnut version");
        }
        Vec::<u8>::default()
    }

    /// Return the doughnut expiry timestamp
    pub fn expiry(&self) -> u32 {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.expiry();
        } else {
            log("Getting expiry failed. Unsupported doughnut version");
        }
        0
    }

    /// Return the doughnut 'not before' timestamp
    pub fn not_before(&self) -> u32 {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.not_before();
        } else {
            log("Getting not_before failed. Unsupported doughnut version");
        }
        0
    }

    /// Return the doughnut payload bytes
    pub fn payload(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.payload();
        } else {
            log("Getting payload failed. Unsupported doughnut version");
        }
        Vec::<u8>::default()
    }

    /// Return the doughnut signature
    pub fn signature(&self) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.signature().to_vec();
        } else {
            log("Getting signature failed. Unsupported doughnut version");
        }
        Vec::<u8>::default()
    }

    /// Return the doughnut signature version
    pub fn signature_version(&self) -> u8 {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.signature_version().into();
        } else {
            log("Getting signature verrsion failed. Unsupported doughnut version");
        }
        0
    }

    /// Return the doughnut payload version
    pub fn payload_version(&self) -> u16 {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.payload_version.into();
        } else {
            log("Getting signature verrsion failed. Unsupported doughnut version");
        }
        0
    }

    /// Return the payload for domain, if it exists in the doughnut
    pub fn domain(&self, domain: &str) -> Vec<u8> {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.get_domain(domain).unwrap().to_vec();
        } else {
            log("Getting domain failed. Unsupported doughnut version");
        }
        Vec::<u8>::default()
    }

    /// Validate the doughnut is usable by a public key (`who`) at the current timestamp (`not_before` <= `now` <= `expiry`)
    pub fn validate(&self, who: &[u8], when: u32) -> bool {
        if let Doughnut::V0(doughnut) = self.0.clone() {
            return doughnut.validate(who, when).is_ok();
        } else {
            log("validating doughnut failed. Unsupported doughnut version");
        }
        false
    }

    /// Encode Doughnut, returned vector of DoughnutHandle as a array of `?` bytes
    pub fn encode(&mut self) -> Vec<u8> {
        self.0.encode()
    }

    /// Decode doughnut with encoded values
    pub fn decode(input: Vec<u8>) -> Self {
        let doughnut = Doughnut::decode(&mut &input[..]).unwrap();
        DoughnutHandle(doughnut)
    }

    /// Verify the signature for the `doughnut`
    pub fn verify(&self) -> bool {
        self.0.verify().is_ok()
    }
}
