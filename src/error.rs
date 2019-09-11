// Copyright 2019 Centrality Investments Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Error type for codec failures
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq, Clone)]
pub enum CodecError<'a> {
    /// The doughnut version is unsupported by the current codec
    UnsupportedVersion,
    /// Invalid encoded format found while decoding
    BadEncoding(&'a str),
}

/// Error type for validation failures
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq, Clone)]
pub enum ValidationError {
    /// Public key attempting to use a doughnut does not match the issued holder
    HolderIdentityMismatched,
    /// The doughnut has expired against the current timestamp
    Expired,
    /// Doughnut use precedes it's 'not before' timestamp, thus it has not matured yet.
    Premature,
    /// A type conversion failed during validation e.g overflow
    Conversion,
}
