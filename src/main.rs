pub mod error;
pub mod v0;

fn main() {
    println!("\nDoughnut v{} 🍩\n", env!("CARGO_PKG_VERSION"));

    let payload: Vec<u8> = vec![
        0, 0, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62,
        185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
        105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138,
        38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 115, 111, 109, 101, 116, 104, 105,
        110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69,
        108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176,
        31, 104, 162, 235, 78, 157, 166, 8, 137, 191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37,
        13, 218, 44, 244, 54, 137, 179, 56, 110, 152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24,
        240, 248, 244, 13, 51, 235, 3, 21, 63, 79, 192, 137, 6,
    ];

    // let s = "0000000000000000110000000001011001111110100101100000111110110000101111101101001010011100101100111001010110001110010101001001100100000100110010110011110100111110101110010100110000101101101000101101110011111110101111001010001110111011001111110010011110111010011100010111111000001100001111000111100110110011010000110110100101111001111101000010011110001001101011100011011101010101101001110100100101101111001100101111100100001010100100011000110101111101011010011000101000100110010111011001000000101101111000000100011011001110111101100111010011000100010111100001000000000000110001000101111000010000000000000111001101101111011011010110010101110100011010000110100101101110011001110000000000000000000000000000000000000000000000000000000000000001000000000111001101101111011011010110010101110100011010000110100101101110011001110100010101101100011100110110010100000000000000000000000000000001000000000000000000000000";
    // let mut payload: Vec<u8> = Default::default();
    // let mut i = 0;
    // loop {
    //     if i + 8 > s.len() {
    //         break
    //     }
    //     let b = u8::from_str_radix(&s[i..i + 8], 2).unwrap();
    //     payload.push(b);
    //     i += 8;
    // }

    println!("encoded length: {:?}", payload.len());
    let d = v0::DoughnutV0::new(&payload).expect("It worked");

    // TODO: Implement as `Display` trait
    println!("payload version: {:?}", d.payload_version());
    println!("signature version: {:?}", d.signature_version());
    println!("issuer: {:?}", d.issuer());
    println!("holder: {:?}", d.holder());
    println!("domain count: {:?}", d.permission_domain_count());
    println!("not before: {:?}", d.not_before());
    println!("expiry: {:?}", d.expiry());
    println!("domains: {:?}", d.domains());
    let doms = d.domains();

    println!("{:?}", doms.get("something"));
    println!("{:?}", doms.get("somethingElse"));

    println!("\n\n");
    println!("Has valid signature?: {:?}", d.verify_signature());

    println!("\n\n");
    println!("raw: {:?}", d);
}
