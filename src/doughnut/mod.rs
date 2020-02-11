// Copyright 2019 Centrality Investments Limited

//!
//! A versioned doughnut wrapper.
//!

use crate::v0::parity::DoughnutV0;
use codec::{Decode, Encode, Error};
use core::convert::TryFrom;

/// A versioned doughnut wrapper. It proxies to the real,inner doughnut type
#[derive(Encode, Decode, Clone, Debug, Eq, PartialEq)]
pub enum Doughnut {
    V0(DoughnutV0),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::v0::parity::DoughnutV0;
    use primitive_types::H512;

    #[test]
    fn versioned_doughnut_v0_works() {
        let domains = vec![("something".to_string(), vec![0, 1, 2, 3, 4])];
        let doughnut_v0 = DoughnutV0 {
            issuer: [1_u8; 32],
            holder: [2_u8; 32],
            domains,
            expiry: 0,
            not_before: None,
            payload_version: 3,
            signature_version: 3,
            signature: H512::default(),
        };

        let doughnut = Doughnut::V0(doughnut_v0.clone());
        let versioned_doughnut = DoughnutV0::try_from(doughnut).unwrap();

        assert_eq!(doughnut_v0, versioned_doughnut);
    }
}
