// Copyright 2022-2023 Futureverse Corporation Limited
//!
//! # TRNNut - Validation
//!
//! Validation trait of TRNNut for use in TRN
//!

use alloc::fmt::{self, Display, Formatter};

/// Error which may occur while validating the permission domain
#[derive(Debug, Eq, PartialEq)]
pub enum ValidationErr<Domain: Display> {
    NoPermission(Domain),
    ConstraintsInterpretation,
}

impl<Domain: Display> Display for ValidationErr<Domain> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPermission(permission_domain) => write!(
                f,
                "TRNNut does not grant permission for {}",
                permission_domain
            ),
            Self::ConstraintsInterpretation => write!(f, "error while interpreting constraints"),
        }
    }
}
