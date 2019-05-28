use core::option::NoneError;

#[derive(Debug)]
pub enum DoughnutErr {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding,
}

impl From<NoneError> for DoughnutErr {
    fn from(_: NoneError) -> Self {
        DoughnutErr::BadEncoding
    }
}