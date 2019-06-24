//!
//! Doughnut traits
//!
use crate::alloc::vec::Vec;

/// A stable API trait to expose doughnut impl data
pub trait DoughnutApi {
    /// The holder and issuer account id type
    type AccountId;
    /// The expiry timestamp type
    type Timestamp;
    /// The signature type
    type Signature;
    /// Return the doughnut holder
    fn holder(&self) -> Self::AccountId;
    /// Return the doughnut issuer
    fn issuer(&self) -> Self::AccountId;
    /// Return the doughnut expiry timestamp
    fn expiry(&self) -> Self::Timestamp;
    /// Return the doughnut payload bytes
    fn payload(&self) -> Vec<u8>;
    /// Return the doughnut signature
    fn signature(&self) -> Self::Signature;
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
}
