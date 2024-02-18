// Copyright 2023-2024 Futureverse Corporation Limited
//!
//! # Topping
//!
//! Topping type.
//!

use alloc::vec::Vec;
use codec::{Decode, Encode, Input, Output};
use core::convert::TryFrom;
use trn_pact::{interpreter::interpret, types::PactType};

use crate::doughnut::topping::{module, PartialDecode, Runtimetopping, ValidationErr, WILDCARD};
use module::Module;

pub const MAX_MODULES: usize = 256;
pub const MAX_METHODS: usize = 128;
pub const VERSION_BYTES: [u8; 2] = [0, 0];
pub const MAX_TOPPING_BYTES: usize = u16::max_value() as usize;

/// A TRN permission topping struct for embedding in doughnuts
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Topping {
    pub modules: Vec<Module>,
}

impl Topping {
    /// Returns the module, if it exists in the Topping
    /// Wildcard modules have lower priority than defined modules
    pub fn get_module(&self, module: &str) -> Option<&Module> {
        let mut outcome: Option<&Module> = None;
        for m in &self.modules {
            if m.name == module {
                outcome = Some(m);
                break;
            } else if m.name == WILDCARD {
                outcome = Some(m);
            }
        }
        outcome
    }
}

impl Encode for Topping {
    fn encode_to<T: Output + ?Sized>(&self, buf: &mut T) {
        if self.modules.is_empty() || self.modules.len() > MAX_MODULES {
            return;
        }
        let module_count = u8::try_from(self.modules.len() - 1);

        // Encode all modules, but make sure each encoding is valid
        // before modifying the output buffer.
        let mut module_payload_buf: Vec<u8> = Vec::<u8>::default();
        for module in &self.modules {
            let mut module_buf: Vec<u8> = Vec::<u8>::default();
            module.encode_to(&mut module_buf);
            if module_buf.is_empty() {
                return;
            }
            module_payload_buf.write(module_buf.as_slice());
        }

        let mut preliminary_buf = Vec::<u8>::default();

        preliminary_buf.write(&VERSION_BYTES);

        preliminary_buf.push_byte(module_count.unwrap());
        preliminary_buf.write(module_payload_buf.as_slice());

        // Avoid writing outside of the allocated topping buffer
        if preliminary_buf.len() <= MAX_TOPPING_BYTES {
            buf.write(preliminary_buf.as_slice());
        }
    }
}

impl PartialDecode for Topping {
    fn partial_decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let module_count = input.read_byte()? + 1;
        let mut modules = Vec::<Module>::default();

        for _ in 0..module_count {
            let m: Module = Decode::decode(input)?;
            modules.push(m);
        }

        Ok(Self { modules })
    }
}

impl Decode for Topping {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let version = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
        if version != 0 {
            return Err(codec::Error::from("expected version : 0"));
        }
        Self::partial_decode(input)
    }
}

impl Topping {
    /// Validates a Topping runtime module by:
    /// (1) looking for `module_name` and `method_name`
    /// (2) executing the Pact interpreter if constraints exist
    ///
    /// # Errors
    ///
    /// Will return error if validation fails with the type of error embedded in `Runtimetopping`
    pub fn validate_module(
        &self,
        module_name: &str,
        method_name: &str,
        args: &[PactType],
    ) -> Result<(), ValidationErr<Runtimetopping>> {
        let module = self
            .get_module(module_name)
            .ok_or_else(|| ValidationErr::NoPermission(Runtimetopping::Module))?;
        let method = module
            .get_method(method_name)
            .ok_or_else(|| ValidationErr::NoPermission(Runtimetopping::Method))?;
        if let Some(pact) = method.get_pact() {
            match interpret(args, pact.data_table.as_ref(), &pact.bytecode) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ValidationErr::NoPermission(Runtimetopping::MethodArguments))
                }
                Err(_) => return Err(ValidationErr::ConstraintsInterpretation),
            }
        }
        Ok(())
    }
}
