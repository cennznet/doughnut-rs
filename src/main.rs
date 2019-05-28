#![feature(try_trait)]

pub mod error;
pub mod v0;

fn main() {
    let s = "
                       .-\"   \"-.
                     .'   . ;   `.
                    /    : . ' :  \
                   |   `  .-. . '  |
                   |  :  (   ) ; ` |
                   |   :  `-'   :  |
                    \\   .` ;  :   /
                     `.   . '   .'
                       `-.___.-'";
    println!("doughnut");
    println!("{:?}", s);
}
