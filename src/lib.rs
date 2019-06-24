#![cfg_attr(not(features = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
#[macro_use]
extern crate std as alloc;

pub mod error;
mod test;
pub mod traits;
pub mod v0;
