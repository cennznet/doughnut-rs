//!
//! Doughnut trait impls
//!
use super::{DoughnutApi, DoughnutVerify};
#[cfg(feature = "std")]
use ed25519_dalek::{PublicKey as Ed25519Pub, Signature as Ed25519Sig};
#[cfg(feature = "std")]
use schnorrkel::{signing_context, PublicKey as Sr25519Pub, Signature as Sr25519Sig};

#[cfg(feature = "std")]
impl<T: DoughnutApi> DoughnutVerify for T
where
    <T as DoughnutApi>::AccountId: AsRef<[u8]>,
    <T as DoughnutApi>::Signature: AsRef<[u8]>,
{
    fn verify(&self) -> bool {
        match self.signature_version() {
            0 => {
                let signature = match Sr25519Sig::from_bytes(self.signature().as_ref()) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                match Sr25519Pub::from_bytes(self.issuer().as_ref()) {
                    Ok(pk) => {
                        // TODO: Parameterise signing context. Hard-coded for now
                        pk.verify(
                            signing_context(b"substrate").bytes(self.payload().as_ref()),
                            &signature,
                        )
                    }
                    Err(_) => return false,
                }
            }
            1 => {
                let signature = match Ed25519Sig::from_bytes(self.signature().as_ref()) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                match Ed25519Pub::from_bytes(self.issuer().as_ref()) {
                    Ok(pk) => match pk.verify(&self.payload(), &signature) {
                        Ok(_) => true,
                        _ => false,
                    },
                    Err(_) => false,
                }
            }
            _ => {
                // Unsupported
                false
            }
        }
    }
}

// Dummy implementation for unit type
impl DoughnutApi for () {
    type AccountId = ();
    type Timestamp = ();
    type Signature = ();
    fn holder(&self) -> Self::AccountId {
        ()
    }
    fn issuer(&self) -> Self::AccountId {
        ()
    }
    fn expiry(&self) -> Self::AccountId {
        ()
    }
    fn payload(&self) -> Vec<u8> {
        Default::default()
    }
    fn signature(&self) -> Self::Signature {
        ()
    }
    fn signature_version(&self) -> u8 {
        255
    }
    fn get_domain(&self, _domain: &str) -> Option<&[u8]> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::DoughnutVerify;
    use crate::v0::parity::DoughnutV0;
    use parity_codec::Decode;

    #[test]
    fn it_verifies_an_sr25519_signed_doughnut() {
        let encoded: Vec<u8> = vec![
            0, 0, 64, 22, 126, 150, 15, 176, 190, 210, 156, 179, 149, 142, 84, 153, 4, 203, 61, 62,
            185, 76, 45, 162, 220, 254, 188, 163, 187, 63, 39, 186, 113, 126, 12, 60, 121, 179, 67,
            105, 121, 244, 39, 137, 174, 55, 85, 167, 73, 111, 50, 249, 10, 145, 141, 125, 105,
            138, 38, 93, 144, 45, 224, 70, 206, 246, 116, 196, 94, 16, 0, 115, 111, 109, 101, 116,
            104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105,
            110, 103, 69, 108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 126, 225, 133, 233, 233, 213, 238,
            3, 88, 7, 202, 58, 150, 82, 73, 106, 220, 150, 238, 21, 220, 55, 194, 201, 68, 82, 182,
            115, 26, 141, 78, 99, 119, 28, 146, 102, 222, 145, 242, 154, 50, 195, 147, 46, 158,
            209, 10, 28, 64, 133, 75, 49, 111, 168, 28, 239, 140, 46, 195, 184, 18, 50, 17, 15,
        ];
        let doughnut: DoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert!(doughnut.verify());
    }

    #[test]
    fn it_verifies_an_ed25519_signed_doughnut() {
        let encoded: Vec<u8> = vec![
            0, 16, 64, 146, 208, 89, 131, 220, 161, 15, 74, 192, 166, 187, 159, 8, 15, 123, 164,
            194, 246, 5, 28, 68, 241, 208, 207, 151, 203, 118, 92, 41, 23, 152, 109, 146, 208, 89,
            131, 220, 161, 15, 74, 192, 166, 187, 159, 8, 15, 123, 164, 194, 246, 5, 28, 68, 241,
            208, 207, 151, 203, 118, 92, 41, 23, 152, 109, 196, 94, 16, 0, 115, 111, 109, 101, 116,
            104, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 128, 0, 115, 111, 109, 101, 116, 104, 105,
            110, 103, 69, 108, 115, 101, 0, 0, 0, 128, 0, 0, 0, 193, 0, 93, 66, 180, 167, 98, 155,
            91, 210, 93, 219, 155, 196, 43, 2, 49, 192, 139, 137, 2, 152, 155, 238, 181, 232, 47,
            89, 196, 16, 189, 116, 132, 74, 64, 49, 115, 237, 225, 216, 85, 238, 183, 255, 196,
            218, 41, 20, 38, 238, 247, 32, 111, 33, 87, 133, 57, 122, 204, 250, 233, 34, 8, 2,
        ];
        let doughnut: DoughnutV0 =
            Decode::decode(&mut &encoded[..]).expect("It is a valid doughnut");
        assert!(doughnut.verify());
    }
}
