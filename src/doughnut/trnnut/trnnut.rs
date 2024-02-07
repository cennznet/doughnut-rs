// Copyright 2022-2023 Futureverse Corporation Limited
//!
//! # TRNNut - V0
//!
//! Version 0 TRNNut type.
//!

use alloc::vec::Vec;
use codec::{Decode, Encode, Input, Output};
use core::convert::TryFrom;
use pact::{interpreter::interpret, types::PactType};

use crate::doughnut::trnnut::{module, PartialDecode, RuntimeDomain, ValidationErr, WILDCARD};
use module::Module;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub const MAX_MODULES: usize = 256;
pub const MAX_METHODS: usize = 128;
pub const VERSION_BYTES: [u8; 2] = [0, 0];
pub const MAX_TRNNUT_BYTES: usize = u16::max_value() as usize;

/// A TRN permission domain struct for embedding in doughnuts
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
pub struct TRNNutV0 {
    pub modules: Vec<Module>,
}

impl TRNNutV0 {
    /// Returns the module, if it exists in the TRNNut
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

impl Encode for TRNNutV0 {
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

        // Avoid writing outside of the allocated domain buffer
        if preliminary_buf.len() <= MAX_TRNNUT_BYTES {
            buf.write(preliminary_buf.as_slice());
        }
    }
}

impl PartialDecode for TRNNutV0 {
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

impl Decode for TRNNutV0 {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let version = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
        if version != 0 {
            return Err(codec::Error::from("expected version : 0"));
        }
        Self::partial_decode(input)
    }
}

impl TRNNutV0 {
    /// Validates a TRNNut runtime module by:
    /// (1) looking for `module_name` and `method_name`
    /// (2) executing the Pact interpreter if constraints exist
    ///
    /// # Errors
    ///
    /// Will return error if validation fails with the type of error embedded in `RuntimeDomain`
    pub fn validate_module(
        &self,
        module_name: &str,
        method_name: &str,
        args: &[PactType],
    ) -> Result<(), ValidationErr<RuntimeDomain>> {
        let module = self
            .get_module(module_name)
            .ok_or_else(|| ValidationErr::NoPermission(RuntimeDomain::Module))?;
        let method = module
            .get_method(method_name)
            .ok_or_else(|| ValidationErr::NoPermission(RuntimeDomain::Method))?;
        if let Some(pact) = method.get_pact() {
            match interpret(args, pact.data_table.as_ref(), &pact.bytecode) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ValidationErr::NoPermission(RuntimeDomain::MethodArguments))
                }
                Err(_) => return Err(ValidationErr::ConstraintsInterpretation),
            }
        }
        Ok(())
    }
}
