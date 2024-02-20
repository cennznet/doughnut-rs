// Copyright 2023-2024 Futureverse Corporation Limited

#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod doughnut;
pub mod error;
pub mod signature;
pub mod traits;

pub use doughnut::topping::Topping;
