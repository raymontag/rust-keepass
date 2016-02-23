use kpdb::v1error::V1KpdbError;

// Todo:
// * Drop for critical data
// * Parsing into LoadParser

#[doc = "
V1Header implements the header of a KeePass v1.x database.
Normally you don't need to mess with this yourself.
"]
#[derive(Clone)]
pub struct V1Header {
    /// File signature
    pub signature1: u32,
    /// File signature
    pub signature2: u32,
    /// Describes which encryption algorithm was used.
    /// 0b10 is for AES, 0b1000 is for Twofish (not
    /// supported, yet)
    pub enc_flag: u32,
    /// Version of the database. 0x00030002 is for v1.x
    pub version: u32,
    /// A seed used to create the final key
    pub final_randomseed: Vec<u8>,
    /// IV for AEC_CBC to de-/encrypt the database
    pub iv: Vec<u8>,
    /// Total number of groups in database
    pub num_groups: u32,
    /// Total number of entries in database
    pub num_entries: u32,
    /// Hash of the encrypted content to check success
    /// of decryption
    pub content_hash: Vec<u8>,
    /// A seed used to create the final key
    pub transf_randomseed: Vec<u8>,
    /// Specifies number of rounds of AES_ECB to create
    /// the final key
    pub key_transf_rounds: u32,
}

impl V1Header {
    /// Use this to create a new empty header
    pub fn new() -> V1Header {
        V1Header {
            signature1: 0,
            signature2: 0,
            enc_flag: 0,
            version: 0,
            final_randomseed: vec![],
            iv: vec![],
            num_groups: 0,
            num_entries: 0,
            content_hash: vec![],
            transf_randomseed: vec![],
            key_transf_rounds: 0,
        }
    }

    // Checks file signatures
    pub fn check_signatures(&self) -> Result<(), V1KpdbError> {
        if self.signature1 != 0x9AA2D903u32 || self.signature2 != 0xB54BFB65u32 {
            return Err(V1KpdbError::SignatureErr);
        }
        Ok(())
    }

    // Checks encryption flag
    pub fn check_enc_flag(&self) -> Result<(), V1KpdbError> {
        if self.enc_flag & 2 != 2 {
            return Err(V1KpdbError::EncFlagErr);
        }
        Ok(())
    }

    // Checks database version
    pub fn check_version(&self) -> Result<(), V1KpdbError> {
        if self.version != 0x00030002u32 {
            return Err(V1KpdbError::VersionErr);
        }
        Ok(())
    }
}
