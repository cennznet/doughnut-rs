// Copyright 2022-2023 Futureverse Corporation Limited

use super::*;
use crate::doughnut::Doughnut;
use crate::traits::{DoughnutApi, DoughnutVerify};
use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::convert::TryFrom;

#[test]
fn it_works_v0() {
    let payload: Vec<u8> = vec![
        // version and domain count
        2, 24, 2, // holder and issuer
        22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62, 185, 76, 45,
        162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67, 105, 121, 244,
        39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138, 38, 93, 144, 45,
        224, 70, 206, 246, 116, // expiry
        35, 122, 8, 0, // Domain 1 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        // Domain 2 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108, 115, 101, 0, 0, 0, 1, 0,
        // Domain data
        0, 0, // signature
        8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176, 31, 104, 162, 235, 78, 157, 166, 8, 137,
        191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37, 13, 218, 44, 244, 54, 137, 179, 56, 110,
        152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24, 240, 248, 244, 13, 51, 235, 3, 21, 63,
        79, 192, 137, 6,
    ];

    let d = DoughnutV0::decode(&mut &payload[..]).expect("It works");

    assert_eq!(d.signature_version, 3);
    assert_eq!(d.payload_version, 2);
    assert_eq!(d.expiry, 555_555);
    assert_eq!(d.not_before, 0);
    assert_eq!(
        d.issuer().as_ref(),
        [
            22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62, 185, 76,
            45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12
        ]
    );
    assert_eq!(
        d.holder().as_ref(),
        [
            60, 121, 179, 67, 105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145,
            141, 125, 105, 138, 38, 93, 144, 45, 224, 70, 206, 246, 116
        ]
    );
    assert_eq!(d.get_domain("something"), Some(&[0_u8][..]));
    assert_eq!(d.get_domain("somethingElse"), Some(&[0_u8][..]));
    assert_eq!(&d.signature[..], &payload[(payload.len() - 64) as usize..],);
    assert_eq!(d.encode(), payload);
}

#[test]
fn v0_encode_two_domains() {
    let payload: Vec<u8> = vec![
        // version and domain count
        0, 0, 2, // holder and issuer
        22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62, 185, 76, 45,
        162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67, 105, 121, 244,
        39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138, 38, 93, 144, 45,
        224, 70, 206, 246, 116, // expiry
        35, 122, 8, 0, // Domain 1 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        // Domain 2 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108, 115, 101, 0, 0, 0, 1, 0,
        // Domain data
        0, 0, // signature
        8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176, 31, 104, 162, 235, 78, 157, 166, 8, 137,
        191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37, 13, 218, 44, 244, 54, 137, 179, 56, 110,
        152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24, 240, 248, 244, 13, 51, 235, 3, 21, 63,
        79, 192, 137, 6,
    ];

    let d = DoughnutV0::decode(&mut &payload[..]).expect("It works");

    let encoded = d.encode();
    assert_eq!(encoded, payload);
}

#[test]
fn v0_encode_one_domain() {
    let payload: Vec<u8> = vec![
        // version and domain count
        0, 0, 0, // holder and issuer
        22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62, 185, 76, 45,
        162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67, 105, 121, 244,
        39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138, 38, 93, 144, 45,
        224, 70, 206, 246, 116, // expiry
        35, 122, 8, 0, // Domain 1 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        // Domain data
        0, // signature
        8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176, 31, 104, 162, 235, 78, 157, 166, 8, 137,
        191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37, 13, 218, 44, 244, 54, 137, 179, 56, 110,
        152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24, 240, 248, 244, 13, 51, 235, 3, 21, 63,
        79, 192, 137, 6,
    ];
    let d = DoughnutV0::decode(&mut &payload[..]).expect("It works");

    let encoded = d.encode();
    assert_eq!(encoded, payload);
}

#[test]
fn v0_ed25519_decode_and_verify() {
    let payload: Vec<u8> = vec![
        // version and domain count
        0, 8, 0, // holder and issuer
        22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62, 185, 76, 45,
        162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67, 105, 121, 244,
        39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138, 38, 93, 144, 45,
        224, 70, 206, 246, 116, // expiry
        35, 122, 8, 0, // Domain 1 header
        115, 111, 109, 101, 116, 104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        // Domain data
        0, // signature
        8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176, 31, 104, 162, 235, 78, 157, 166, 8, 137,
        191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37, 13, 218, 44, 244, 54, 137, 179, 56, 110,
        152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24, 240, 248, 244, 13, 51, 235, 3, 21, 63,
        79, 192, 137, 6,
    ];
    let d = DoughnutV0::decode(&mut &payload[..]).expect("It works");
    assert_eq!(d.signature_version(), 1);
    assert_eq!(d.payload(), &payload[..payload.len() - 64]);
}

#[test]
fn versioned_enum_v0_sr25519_verification() {
    //secret_key = '144,163,100,97,49,159,86,228,92,140,127,112,43,188,131,181,210,140,151,174,242,211,188,33,78,120,171,88,62,216,36,27,191,76,36,231,117,200,17,43,19,67,131,11,240,239,145,240,172,233,122,81,210,6,60,252,89,141,205,76,109,195,143,233'
    let encoded: Vec<u8> = vec![
        0x00, 0x00, 0x03, // version and domain count
        0xec, 0xcf, 0x24, 0x61, 0xda, 0x1f, 0x1c, 0x54, 0x48, 0xc2, 0x60, 0xec, 0x7f, 0xea, 0x89,
        0x0c, // issuer
        0x74, 0x37, 0x1a, 0xe3, 0x4a, 0xdd, 0xed, 0xd9, 0xa2, 0x46, 0x39, 0x0a, 0x45, 0x8b, 0x28,
        0x3b, 0x1b, 0x89, 0x41, 0x1d, 0xb6, 0x19, 0x9d, 0x3d, 0xe2, 0x0d, 0xe6, 0x0e, 0x6f, 0x06,
        0x19, 0xba, // holder
        0xe3, 0x75, 0xb1, 0xf4, 0xac, 0x93, 0x28, 0x77, 0xd1, 0x4e, 0x0d, 0x6d, 0xec, 0x77, 0xcd,
        0xca, 0xb1, 0x68, 0xde, // Expiry
        0x3a, 0x39, 0x30, 0x00, // Not Before
        0x00, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0a, 0x00, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x32, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x54, 0xcb, 0xc8, 0x9f, 0xe6, 0x9b, 0x0e,
        0xd8, 0x43, 0x3c, 0x42, 0x3a, 0x15, 0x17, 0x1f, 0x6b, 0x72, 0x2b, 0x99, 0x63, 0x81, 0xf5,
        0xf4, 0x64, 0xce, 0xbd, 0x20, 0x7f, 0xf1, 0xfb, 0xf8, 0x07, 0x8d, 0xd5, 0xe5, 0x9d, 0x50,
        0xb4, 0x1c, 0x13, 0x59, 0xfe, 0x92, 0x45, 0x5b, 0x4a, 0x5b, 0x88, 0xa5, 0x20, 0x21, 0x24,
        0xcf, 0xf3, 0x7e, 0x6b, 0x27, 0xd1, 0x9d, 0x86, 0xfa, 0xf9, 0xd5,
        0x81, // Domain & signature
    ];
    let doughnut = Doughnut::decode(&mut &encoded[..]).expect("It works");
    let d = DoughnutV0::try_from(doughnut.clone()).unwrap();
    assert_eq!(d.verify(), Ok(()));

    assert_eq!(d.signature_version, 0);
    assert_eq!(d.payload_version, 0);
    assert_eq!(d.expiry, 987654321);
    assert_eq!(d.not_before, 12345);

    assert_eq!(
        d.holder,
        [
            0x1b, 0x89, 0x41, 0x1d, 0xb6, 0x19, 0x9d, 0x3d, 0xe2, 0x0d, 0xe6, 0x0e, 0x6f, 0x06,
            0x19, 0xba, 0xe3, 0x75, 0xb1, 0xf4, 0xac, 0x93, 0x28, 0x77, 0xd1, 0x4e, 0x0d, 0x6d,
            0xec, 0x77, 0xcd, 0xca
        ]
    );
    assert_eq!(
        d.issuer,
        [
            0xec, 0xcf, 0x24, 0x61, 0xda, 0x1f, 0x1c, 0x54, 0x48, 0xc2, 0x60, 0xec, 0x7f, 0xea,
            0x89, 0x0c, 0x74, 0x37, 0x1a, 0xe3, 0x4a, 0xdd, 0xed, 0xd9, 0xa2, 0x46, 0x39, 0x0a,
            0x45, 0x8b, 0x28, 0x3b
        ]
    );
    assert_eq!(
        d.domains[0],
        ("Domain 1".to_string(), vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    );
    assert_eq!(
        d.domains[1],
        ("Domain 2".to_string(), vec![10, 11, 12, 13, 14, 15])
    );
    assert_eq!(d.domains.len(), 2);

    assert_eq!(doughnut.encode(), encoded);
}

#[test]
fn versioned_enum_v0_ed25519_verification() {
    let encoded: Vec<u8> = vec![
        0x00, 0x08, 0x03, 0xe3, 0x84, 0x94, 0x29, 0xae, 0x4e, 0xfb, 0xb0, 0x93, 0xea, 0x8a, 0xe2,
        0x70, 0xeb, 0xdb, 0x57, 0xd0, 0x61, 0x2c, 0x30, 0x0e, 0x2c, 0x5d, 0xde, 0x8c, 0xa6, 0x4d,
        0x14, 0x81, 0x83, 0x3e, 0x6f, 0x1b, 0x89, 0x41, 0x1d, 0xb6, 0x19, 0x9d, 0x3d, 0xe2, 0x0d,
        0xe6, 0x0e, 0x6f, 0x06, 0x19, 0xba, 0xe3, 0x75, 0xb1, 0xf4, 0xac, 0x93, 0x28, 0x77, 0xd1,
        0x4e, 0x0d, 0x6d, 0xec, 0x77, 0xcd, 0xca, 0xb1, 0x68, 0xde, 0x3a, 0x39, 0x30, 0x00, 0x00,
        0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x32, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x80, 0x9d, 0x7a, 0xd2, 0xe5, 0x27, 0x79, 0x30,
        0x06, 0xea, 0xaf, 0xf7, 0x56, 0xa0, 0xae, 0xb8, 0x97, 0x1d, 0xd3, 0xc1, 0x11, 0xc7, 0x0a,
        0xda, 0xae, 0x4f, 0xc2, 0x2e, 0xba, 0x07, 0x3f, 0xb1, 0x82, 0x10, 0xed, 0xad, 0x73, 0xe4,
        0x4d, 0xe6, 0xd2, 0x35, 0x12, 0xb4, 0x8c, 0x93, 0x74, 0xab, 0xd7, 0x78, 0x6f, 0x5c, 0xbe,
        0xd5, 0x51, 0xa5, 0xe2, 0xdb, 0xe7, 0x93, 0x98, 0x39, 0xc1, 0x0b,
    ];
    let doughnut = Doughnut::decode(&mut &encoded[..]).expect("It works");
    let d = DoughnutV0::try_from(doughnut.clone()).unwrap();

    assert_eq!(d.verify(), Ok(()));

    assert_eq!(d.signature_version, 1);
    assert_eq!(d.payload_version, 0);
    assert_eq!(d.expiry, 987654321);
    assert_eq!(d.not_before, 12345);

    assert_eq!(
        d.holder,
        [
            0x1b, 0x89, 0x41, 0x1d, 0xb6, 0x19, 0x9d, 0x3d, 0xe2, 0x0d, 0xe6, 0x0e, 0x6f, 0x06,
            0x19, 0xba, 0xe3, 0x75, 0xb1, 0xf4, 0xac, 0x93, 0x28, 0x77, 0xd1, 0x4e, 0x0d, 0x6d,
            0xec, 0x77, 0xcd, 0xca
        ]
    );
    assert_eq!(
        d.issuer,
        [
            0xe3, 0x84, 0x94, 0x29, 0xae, 0x4e, 0xfb, 0xb0, 0x93, 0xea, 0x8a, 0xe2, 0x70, 0xeb,
            0xdb, 0x57, 0xd0, 0x61, 0x2c, 0x30, 0x0e, 0x2c, 0x5d, 0xde, 0x8c, 0xa6, 0x4d, 0x14,
            0x81, 0x83, 0x3e, 0x6f
        ]
    );
    assert_eq!(
        d.domains[0],
        ("Domain 1".to_string(), vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    );
    assert_eq!(
        d.domains[1],
        ("Domain 2".to_string(), vec![10, 11, 12, 13, 14, 15])
    );
    assert_eq!(d.domains.len(), 2);

    assert_eq!(doughnut.encode(), encoded);
}
