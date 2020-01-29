// Copyright 2020 Centrality Investments Limited
use wasm_bindgen::prelude::*;
use crate::doughnut::Doughnut;
use crate::v0::parity::DoughnutV0;

// Allow users to create, sign, and inspect doughnuts in JS
// Maybe use closures to pass in signer
// Builder-ish patter to make doughnuts

// Can we just return a "doughnut handle" to JS but never pass the actual doughnut over the API boundary?

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
#[derive(Clone)]
pub struct DoughnutHandle(Doughnut);

#[wasm_bindgen]
impl DoughnutHandle {
    /// Create a new Doughnut, it is always v0 for now
    pub fn new() -> Self {
        DoughnutHandle(Doughnut::V0(DoughnutV0::default()))
    }

    /// Set this doughnut's issuing public key
    pub fn issuer(&mut self, issuer: Vec<u8>) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            doughnut.issuer = from_slice(&issuer);
        } else {
            log("Setting issuer failed. Unsupported doughnut version");
        }
        self.clone()
    }
    /// Set this doughnut's holding public key
    pub fn holder(&mut self, holder: Vec<u8>) -> Self {
        if let Doughnut::V0(mut doughnut) = self.0.clone() {
            doughnut.holder = from_slice(&holder);
        } else {
            log("Setting holder failed. Unsupported doughnut version");
        }
        self.clone()
    }
}

// new doughnut
//     .issuer(1)
//     .holder(2)
//     .expiry(555)
//     .not_before(123)
//     .add_domain("cennznet", vec![1,2,3,4,5])
//     .add_domain("plug", vec![1,2,3])
//     .sign(keyring.address);

    // 1) "Doughnut Handle", has a ref to where the doughnut is
    // 2) mutable sign method
    // 3) Public "getters" for inspecting fields
    // 4) encode method
    // 5) decode method
