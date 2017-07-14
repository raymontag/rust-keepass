use std::fmt;
use std::error;

pub use self::CommonError::*;

#[doc = "
Use this for catching various errors that
can happen when using V1Kpdb.
"]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum CommonError {
    /// Some error in parsing
    ConvertErr,
}

impl fmt::Display for CommonError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(error::Error::description(self))
    }
}

impl error::Error for CommonError {
    fn description(&self) -> &str {
        match *self {
            ConvertErr => "Some error while converting datatypes",
        }
    }
}
