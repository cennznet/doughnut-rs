pub mod error;
mod test;
pub mod v0;

fn main() {
    println!("\nDoughnut v{} 🍩\n", env!("CARGO_PKG_VERSION"));
}
