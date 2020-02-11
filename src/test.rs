// Copyright 2019 Centrality Investments Limited

#![cfg(test)]

use alloc::vec::Vec;

use crate::doughnut::Doughnut;
use crate::traits::DoughnutApi;
use crate::v0::{parity, DoughnutV0};
use codec::{Decode, Encode};
use core::convert::TryFrom;
use parity::DoughnutV0 as ParityDoughnutV0;

#[test]
fn it_works_v0() {
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
    let d = DoughnutV0::new(&payload).expect("It works");

    assert_eq!(d.signature_version(), 0);
    assert_eq!(d.payload_version(), 0);
    assert_eq!(d.expiry(), 555_555);
    assert_eq!(d.not_before(), 0);
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

    assert_eq!(
        d.signature().to_vec(),
        payload[(payload.len() - 64) as usize..].to_vec()
    );

    assert_eq!(d.encode(), payload);
}

#[test]
fn it_works_v0_parity() {
    let payload: Vec<u8> = vec![
        64, 24, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62,
        185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
        105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138,
        38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 115, 111, 109, 101, 116, 104, 105,
        110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69,
        108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176,
        31, 104, 162, 235, 78, 157, 166, 8, 137, 191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37,
        13, 218, 44, 244, 54, 137, 179, 56, 110, 152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24,
        240, 248, 244, 13, 51, 235, 3, 21, 63, 79, 192, 137, 6,
    ];
    let d = ParityDoughnutV0::decode(&mut &payload[..]).expect("It works");

    assert_eq!(d.signature_version, 3);
    assert_eq!(d.payload_version, 2);
    assert_eq!(d.expiry, 555_555);
    assert_eq!(d.not_before, None);
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
fn v0_parity_encode_two_domains() {
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
    let d = ParityDoughnutV0::decode(&mut &payload[..]).expect("It works");

    let encoded = d.encode();
    assert_eq!(encoded, payload);
}

#[test]
fn v0_parity_encode_one_domain() {
    let payload: Vec<u8> = vec![
        0, 0, 0, 140, 188, 8, 233, 191, 184, 226, 62, 44, 40, 70, 61, 119, 253, 198, 169, 5, 174,
        21, 221, 88, 142, 59, 183, 158, 100, 101, 155, 11, 141, 209, 82, 142, 175, 4, 21, 22, 135,
        115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97, 54, 147, 201, 18, 144, 156, 178, 38,
        170, 71, 148, 242, 106, 72, 5, 131, 96, 186, 99, 101, 110, 110, 122, 110, 101, 116, 0, 0,
        0, 0, 0, 0, 0, 0, 146, 0, 0, 0, 128, 64, 103, 101, 110, 101, 114, 105, 99, 45, 97, 115,
        115, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 116, 114, 97,
        110, 115, 102, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 38, 0, 0, 0, 132, 108, 206, 45, 58, 91, 16, 85, 224, 70, 129, 238, 28, 147, 6, 139,
        121, 74, 53, 95, 249, 75, 83, 74, 212, 178, 6, 217, 251, 131, 232, 45, 230, 220, 85, 16,
        221, 118, 92, 200, 161, 122, 95, 133, 241, 96, 234, 67, 56, 21, 170, 217, 46, 217, 214,
        237, 1, 16, 48, 2, 27, 91, 15, 9,
    ];
    let d = ParityDoughnutV0::decode(&mut &payload[..]).expect("It works");

    let encoded = d.encode();
    assert_eq!(encoded, payload);
}

#[test]
fn it_works_v0_parity_ed25519() {
    let payload: Vec<u8> = vec![
        0, 16, 64, 146, 208, 89, 131, 220, 161, 15, 74, 192, 166, 187, 159, 8, 15, 123, 164, 194,
        246, 5, 28, 68, 241, 208, 207, 151, 203, 118, 92, 41, 23, 152, 109, 146, 208, 89, 131, 220,
        161, 15, 74, 192, 166, 187, 159, 8, 15, 123, 164, 194, 246, 5, 28, 68, 241, 208, 207, 151,
        203, 118, 92, 41, 23, 152, 109, 196, 94, 16, 0, 115, 111, 109, 101, 116, 104, 105, 110,
        103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69, 108,
        115, 101, 0, 0, 0, 128, 0, 0, 0, 193, 0, 93, 66, 180, 167, 98, 155, 91, 210, 93, 219, 155,
        196, 43, 2, 49, 192, 139, 137, 2, 152, 155, 238, 181, 232, 47, 89, 196, 16, 189, 116, 132,
        74, 64, 49, 115, 237, 225, 216, 85, 238, 183, 255, 196, 218, 41, 20, 38, 238, 247, 32, 111,
        33, 87, 133, 57, 122, 204, 250, 233, 34, 8, 2,
    ];
    let d = ParityDoughnutV0::decode(&mut &payload[..]).expect("It works");
    assert_eq!(d.signature_version(), 1);
    assert_eq!(d.payload(), &payload[..payload.len() - 64]);
}

#[test]
fn it_works_doughnut_enum_v0_parity() {
    let payload: Vec<u8> = vec![
        0, 64, 24, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61,
        62, 185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
        105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105, 138,
        38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 115, 111, 109, 101, 116, 104, 105,
        110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105, 110, 103, 69,
        108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 8, 185, 184, 138, 72, 86, 187, 125, 166, 109, 176,
        31, 104, 162, 235, 78, 157, 166, 8, 137, 191, 33, 202, 128, 138, 165, 73, 244, 67, 247, 37,
        13, 218, 44, 244, 54, 137, 179, 56, 110, 152, 170, 180, 218, 107, 177, 170, 58, 91, 62, 24,
        240, 248, 244, 13, 51, 235, 3, 21, 63, 79, 192, 137, 6,
    ];
    let doughnut = Doughnut::decode(&mut &payload[..]).expect("It works");
    let d = ParityDoughnutV0::try_from(doughnut.clone()).unwrap();

    assert_eq!(d.signature_version, 3);
    assert_eq!(d.payload_version, 2);
    assert_eq!(d.expiry, 555_555);
    assert_eq!(d.not_before, None);
    assert_eq!(d.encode(), payload[1..].to_vec());
    assert_eq!(doughnut.encode(), payload);
}
