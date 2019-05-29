#[derive(Debug)]
pub enum DoughnutErr<'a> {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding(&'a str),
}
