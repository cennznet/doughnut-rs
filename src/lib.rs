#![no_std]
#![feature(alloc)]
#![feature(raw)]

#[cfg_attr(test, macro_use)]
extern crate alloc;

pub mod error;
mod test;
pub mod traits;
pub mod v0;
