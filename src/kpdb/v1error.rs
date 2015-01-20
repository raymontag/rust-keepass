#[doc = "
Use this for catching various errors that
can happen when using V1Kpdb.
"]
pub enum V1KpdbError {
    /// Couldn't open the database or file is to
    /// small.
    FileErr,
    /// Something went wrong while the database is
    /// readed in
    ReadErr,
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
}
