// Copyright 2023-2024 Futureverse Corporation Limited

//!
//! A versioned doughnut wrapper.
//!

use codec::{Decode, Encode, Error, Input, Output};
use core::convert::TryFrom;

mod v0;
mod v1;

pub mod topping;

use crate::traits::{DecodeInner, PayloadVersion};
pub use v0::DoughnutV0;
pub use v1::DoughnutV1;

#[cfg(test)]
mod tests;

pub const SIGNATURE_MASK: u8 = 0b0001_1111;
pub const SIGNATURE_OFFSET: usize = 11;
pub const VERSION_MASK: u16 = 0b0000_0111_1111_1111;

/// A versioned doughnut wrapper.
/// Its codec implementation is transparent, proxying to the real, inner doughnut version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Doughnut {
    V0(DoughnutV0),
    V1(DoughnutV1),
}

impl Encode for Doughnut {
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        match self {
            // encode transparently
            Doughnut::V0(inner) => inner.encode_to(dest),
            Doughnut::V1(inner) => inner.encode_to(dest),
        }
    }
}

impl Decode for Doughnut {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let version_data = u16::from_le_bytes([input.read_byte()?, input.read_byte()?]);
        let payload_version = version_data & VERSION_MASK;
        let signature_version = ((version_data >> SIGNATURE_OFFSET) as u8) & SIGNATURE_MASK;

        match payload_version
            .try_into()
            .map_err(|_| Error::from("invalid doughnut version"))?
        {
            PayloadVersion::V0 => {
                let mut doughnut_v0 = DoughnutV0::decode_inner(input, false)?;
                doughnut_v0.payload_version = payload_version;
                doughnut_v0.signature_version = signature_version;
                Ok(Doughnut::V0(doughnut_v0))
            }
            PayloadVersion::V1 => {
                let mut doughnut_v1 = DoughnutV1::decode_inner(input, false)?;
                doughnut_v1.payload_version = payload_version;
                doughnut_v1.signature_version = signature_version;
                Ok(Doughnut::V1(doughnut_v1))
            }
        }
    }
}

#[allow(irrefutable_let_patterns)]
impl TryFrom<Doughnut> for DoughnutV0 {
    type Error = Error;
    fn try_from(v: Doughnut) -> Result<Self, Self::Error> {
        if let Doughnut::V0(inner) = v {
            return Ok(inner);
        }
        Err(Error::from("Doughnut version is not 0"))
    }
}

#[allow(irrefutable_let_patterns)]
impl TryFrom<Doughnut> for DoughnutV1 {
    type Error = Error;
    fn try_from(v: Doughnut) -> Result<Self, Self::Error> {
        if let Doughnut::V1(inner) = v {
            return Ok(inner);
        }
        Err(Error::from("Doughnut version is not 1"))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::doughnut::v0::DoughnutV0;
    use crate::signature::SignatureVersion;
    use primitive_types::H512;

    #[test]
    fn versioned_doughnut_v0_works() {
        let toppings = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v0 = DoughnutV0 {
            issuer: [1_u8; 32],
            holder: [2_u8; 32],
            toppings,
            expiry: 0,
            not_before: 0,
            payload_version: 3,
            signature_version: 3,
            signature: H512::default(),
        };

        let doughnut = Doughnut::V0(doughnut_v0.clone());
        let versioned_doughnut = DoughnutV0::try_from(doughnut).unwrap();

        assert_eq!(doughnut_v0, versioned_doughnut);
    }

    #[test]
    fn versioned_doughnut_v0_codec_is_transparent() {
        let toppings = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v0 = DoughnutV0 {
            issuer: [1_u8; 32],
            holder: [2_u8; 32],
            toppings,
            expiry: 0,
            not_before: 0,
            payload_version: PayloadVersion::V0 as u16,
            signature_version: SignatureVersion::Ed25519 as u8,
            signature: H512::default(),
        };
        let expected = doughnut_v0.encode();

        assert_eq!(expected, Doughnut::V0(doughnut_v0.clone()).encode());

        assert_eq!(
            Doughnut::V0(doughnut_v0),
            Doughnut::decode(&mut &expected[..]).expect("it decodes")
        );
    }

    #[test]
    fn versioned_doughnut_v1_codec_is_transparent() {
        let toppings = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v1 = DoughnutV1 {
            issuer: [1_u8; 33],
            holder: [2_u8; 33],
            fee_mode: 0,
            toppings,
            expiry: 0,
            not_before: 0,
            payload_version: PayloadVersion::V1 as u16,
            signature_version: SignatureVersion::ECDSA as u8,
            signature: [0_u8; 65],
        };
        let expected = doughnut_v1.encode();

        assert_eq!(expected, Doughnut::V1(doughnut_v1.clone()).encode());

        assert_eq!(
            Doughnut::V1(doughnut_v1),
            Doughnut::decode(&mut &expected[..]).expect("it decodes")
        );
    }
}
