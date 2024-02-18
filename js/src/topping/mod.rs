// Copyright 2023-2024 Futureverse Corporation Limited

//! Provide JS-Rust API bindings to create and inspect Topping

extern crate alloc;

use alloc::{format, vec::Vec};
use codec::{Decode, Encode};
use doughnut_rs::doughnut::topping::{module::Module, Topping};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen(typescript_custom_section)]
const MODULE_METHOD_TYPE_DEFINITION: &str = r#"
/** Method configuration for modules. */
export type ModuleMethod = {
    /** Method name */
    readonly name: string;
    /** Block cooldown */
    readonly blockCooldown?: number;
    /** Constraints */
    readonly constraints?: Uint8Array;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ModuleMethod")]
    pub type ModuleMethodJS;
}

#[wasm_bindgen(typescript_custom_section)]
const MODULE_TYPE_DEFINITION: &str = r#"
/** Module configuration.  */
export type Module = {
    /** Module name */
    readonly name: string;
    /** Block cooldown */
    readonly blockCooldown?: number;
    /** Methods - i.e. module extrinsics */
    readonly methods: ReadonlyArray<ModuleMethod>;
};
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Module")]
    pub type ModuleJS;
}

/// A js handle/wrapper for a rust versioned topping struct
#[wasm_bindgen(js_name = Topping)]
pub struct ToppingJS(Topping);

#[wasm_bindgen(js_class = Topping)]
#[allow(irrefutable_let_patterns)]
impl ToppingJS {
    #[wasm_bindgen(constructor)]
    /// Create a new Topping, it is always v0 for now
    pub fn new(modules: &JsValue) -> Self {
        console_error_panic_hook::set_once();

        let modules: Vec<Module> = serde_wasm_bindgen::from_value(modules.clone())
            .expect("Deserialization of modules failed");

        let topping: Topping = Topping { modules };
        ToppingJS(topping)
    }

    #[wasm_bindgen(js_name = getModule)]
    pub fn get_module(&self, module: &str) -> JsValue {
        self.0
            .get_module(module)
            .map(|module| serde_wasm_bindgen::to_value(&module).unwrap_or(JsValue::UNDEFINED))
            .unwrap_or(JsValue::UNDEFINED)
    }

    /// Encode the topping into bytes
    pub fn encode(&mut self) -> Vec<u8> {
        self.0.encode()
    }

    /// Decode a version 0 topping from `input` bytes
    pub fn decode(input: &[u8]) -> Result<ToppingJS, JsValue> {
        match Topping::decode(&mut &input[..]) {
            Ok(topping) => Ok(ToppingJS(topping)),
            Err(err) => {
                log(&format!("failed decoding: {:?}", err));
                Err(JsValue::undefined())
            }
        }
    }
}

// /// A js handle/wrapper for a rust versioned module
// #[derive(serde::Deserialize)]
// #[wasm_bindgen(js_name = Module)]
// pub struct ModuleJS(Module);

// #[wasm_bindgen(js_class = Module)]
// #[allow(irrefutable_let_patterns)]
// impl ModuleJS {
//     #[wasm_bindgen(constructor)]
//     /// Create a new Module
//     pub fn new(name: &str, block_cooldown: u32, methods: JsValue) -> Self {
//         console_error_panic_hook::set_once();

//         let methods: Vec<Method> = methods
//             .into_serde()
//             .expect("Deserialization of methods failed");

//         let module = Module::new(name)
//             .block_cooldown(block_cooldown)
//             .methods(vec![]);

//         ModuleJS(module)
//     }

//     /// Encode the module into bytes
//     pub fn encode(&mut self) -> Vec<u8> {
//         self.0.encode()
//     }
// }

// /// A js handle/wrapper for a rust versioned Method struct
// #[derive(serde::Deserialize)]
// #[wasm_bindgen(js_name = Method)]
// pub struct MethodJS(Method);

// #[wasm_bindgen(js_class = Method)]
// #[allow(irrefutable_let_patterns)]
// impl MethodJS {
//     #[wasm_bindgen(constructor)]
//     /// Create a new Method
//     pub fn new(name: &str, block_cooldown: u32, constraints: Vec<u8>) -> Self {
//         console_error_panic_hook::set_once();

//         let method = Method::new(name)
//             .block_cooldown(block_cooldown)
//             .constraints(constraints);

//         MethodJS(method)
//     }

//     /// Encode the method into bytes
//     pub fn encode(&mut self) -> Vec<u8> {
//         self.0.encode()
//     }
// }
