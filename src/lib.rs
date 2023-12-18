// Copyright 2019-2020 Centrality Investments Limited

#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
#[macro_use]
extern crate std as alloc;

mod doughnut;
pub use doughnut::Doughnut;

pub mod error;
#[cfg(feature = "crypto")]
pub mod signature;
mod test;
pub mod traits;
pub mod v0;
pub mod v1;
