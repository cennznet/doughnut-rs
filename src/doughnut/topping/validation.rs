// Copyright 2023-2024 Futureverse Corporation Limited
//!
//! # Topping - Validation
//!
//! Validation trait of Topping for use in TRN
//!

use alloc::fmt::{self, Display, Formatter};

/// Error which may occur while validating the permission topping
#[derive(Debug, Eq, PartialEq)]
pub enum ValidationErr<Topping: Display> {
    NoPermission(Topping),
    ConstraintsInterpretation,
}

impl<Topping: Display> Display for ValidationErr<Topping> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPermission(permission_topping) => write!(
                f,
                "Topping does not grant permission for {}",
                permission_topping
            ),
            Self::ConstraintsInterpretation => write!(f, "error while interpreting constraints"),
        }
    }
}
