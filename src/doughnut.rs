// Copyright 2019-2020 Centrality Investments Limited

//!
//! A versioned doughnut wrapper.
//!

use crate::v0::DoughnutV0;
use codec::{Decode, Encode, Error, Input, Output};
use core::convert::TryFrom;
use crate::v1::DoughnutV1;

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
        // TODO: check the first byte without consuming and proxy to the correct decoder version
        // for now try decode a version 0 no matter what, as that is the only type that exists.
        // TODO: fix decode according to the version
        Ok(Doughnut::V1(DoughnutV1::decode(input)?))
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
    use crate::v0::DoughnutV0;
    use primitive_types::H512;

    #[test]
    fn versioned_doughnut_v0_works() {
        let domains = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v0 = DoughnutV0 {
            issuer: [1_u8; 32],
            holder: [2_u8; 32],
            domains,
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
        let domains = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v0 = DoughnutV0 {
            issuer: [1_u8; 32],
            holder: [2_u8; 32],
            domains,
            expiry: 0,
            not_before: 0,
            payload_version: 3,
            signature_version: 3,
            signature: H512::default(),
        };
        let expected = doughnut_v0.encode();

        assert_eq!(expected, Doughnut::V0(doughnut_v0.clone()).encode());

        assert_eq!(
            Doughnut::V0(doughnut_v0),
            Doughnut::decode(&mut &expected[..]).expect("it decodes")
        );
    }
}
