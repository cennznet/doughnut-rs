#[derive(Debug)]
pub enum DoughnutErr {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding(&'static str),
}