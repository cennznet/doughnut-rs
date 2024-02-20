// Copyright 2023-2024 Futureverse Corporation Limited
//! # Topping
//!
//! Delegated authority topping for TRN
//!

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

extern crate alloc;

pub use core::convert::TryFrom;

use alloc::fmt::{self, Display, Formatter};
use codec::Input;

pub mod method;
pub mod module;
pub mod topping;
pub mod validation;

pub use crate::{
    doughnut::topping::topping::Topping, doughnut::topping::validation::ValidationErr,
};

#[cfg(test)]
mod tests;

pub const WILDCARD: &str = "*";

/// A TRN module permission topping
#[derive(Debug, Eq, PartialEq)]
pub enum Runtimetopping {
    Method,
    MethodArguments,
    Module,
}

impl Display for Runtimetopping {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Method => write!(f, "method"),
            Self::MethodArguments => write!(f, "method arguments"),
            Self::Module => write!(f, "module"),
        }
    }
}

pub trait PartialDecode: Sized {
    /// decode an input which is not including the version as the up front two bytes
    ///
    /// # Errors
    ///
    /// On failure, returns a `codec::Error`
    fn partial_decode<I: Input>(input: &mut I) -> Result<Self, codec::Error>;
}
