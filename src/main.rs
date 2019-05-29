
pub mod error;
pub mod v0;

fn main() {
    println!("\nDoughnut v{} 🍩\n", env!("CARGO_PKG_VERSION"));

    let payload0: Vec<u8> = vec![
        0, 0, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62,
        185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
        105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138,
        38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // println!("encoded length: {:?}", payload0.len());
    let d = v0::DoughnutV0::new(&payload0).expect("It worked");

    // TODO: Implement as `Display` trait
    println!("payload version: {:?}", d.payload_version());
    println!("signature version: {:?}", d.signature_version());
    println!("issuer: {:?}", d.issuer());
    println!("holder: {:?}", d.holder());
    println!("domain count: {:?}", d.permission_domain_count());
    println!("not before: {:?}", d.not_before());
    println!("expiry: {:?}", d.expiry());

    println!("\n\n");
    println!("raw: {:?}", d);
}
