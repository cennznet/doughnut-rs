// Copyright 2019-2020 Centrality Investments Limited

#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod doughnut;
pub mod error;
#[cfg(feature = "crypto")]
pub mod signature;
pub mod traits;
