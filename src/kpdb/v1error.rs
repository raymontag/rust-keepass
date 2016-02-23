use std::fmt;
use std::error;

pub use self::V1KpdbError::*;

#[doc = "
Use this for catching various errors that
can happen when using V1Kpdb.
"]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum V1KpdbError {
    /// E.g. Couldn't open a file or file is to
    /// small.
    FileErr,
    /// Something went wrong while the database is
    /// readed in
    ReadErr,
    /// Something went wrong while the database was written
    WriteErr,
    /// The file signature in the header is wrong
    SignatureErr,
    /// Not supported encryption used
    EncFlagErr,
    /// Wrong database version
    VersionErr,
    /// Some error in decryption
    DecryptErr,
    /// Hash of decrypted content is wrong.
    /// Probably the wrong password and/or keyfile
    /// was used
    HashErr,
    /// Some error in parsing
    ConvertErr,
    /// Some error in parsing. Probably corrupted database
    OffsetErr,
    /// Group tree is corrupted
    TreeErr,
    /// Password and/or keyfile needed but at least one of both
    PassErr,
    /// Can't find item in Vec
    IndexErr,
    /// Tried upgrade of weak reference without strong one
    WeakErr,
}

impl fmt::Display for V1KpdbError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(error::Error::description(self))
    }
}

impl error::Error for V1KpdbError {
    fn description(&self) -> &str {
        match *self {
            FileErr => "Couldn't open file or database is too small",
            ReadErr => "Couldn't read file",
            WriteErr => "Couldn't write file",
            SignatureErr => "File signature in header is wrong",
            EncFlagErr => "Encryption algorithm not supported",
            VersionErr => "Wrong database version",
            DecryptErr => "Something went wrong during decryption",
            HashErr => "Content's hash is wrong, probably wrong password",
            ConvertErr => "Some error while parsing the database",
            OffsetErr => "Some error while parsing the database. Probably a corrupted file",
            TreeErr => "Group tree is corrupted",
            PassErr => "Password and/or keyfile needed but at least one of both",
            IndexErr => "Can't find item in Vec",
            WeakErr => "Tried upgrade of weak reference without strong one",
        }
    }
}
