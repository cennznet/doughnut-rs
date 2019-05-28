#![feature(try_trait)]

pub mod error;
pub mod v0;

fn main() {
    println!("Doughnut v{} 🍩", env!("CARGO_PKG_VERSION"));
}
