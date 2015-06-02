use std::fs::File;
use std::io::Read;

use kpdb::common::slice_to_u32;
use kpdb::v1error::V1KpdbError;

#[doc = "
V1Header implements the header of a KeePass v1.x database.
Normally you don't need to mess with this yourself.
"]
pub struct V1Header {
    /// File signature
    pub signature1:        u32,
    /// File signature
    pub signature2:        u32,
    /// Describes which encryption algorithm was used.
    /// 0b10 is for AES, 0b1000 is for Twofish (not
    /// supported, yet)
    pub enc_flag:          u32,
    /// Version of the database. 0x00030002 is for v1.x
    pub version:           u32,
    /// A seed used to create the final key
    pub final_randomseed:  Vec<u8>,
    /// IV for AEC_CBC to de-/encrypt the database
    pub iv:                Vec<u8>,
    /// Total number of groups in database
    pub num_groups:        u32,
    /// Total number of entries in database
    pub num_entries:       u32,
    /// Hash of the encrypted content to check success
    /// of decryption
    pub contents_hash:     Vec<u8>,
    /// A seed used to create the final key
    pub transf_randomseed: Vec<u8>,
    /// Specifies number of rounds of AES_ECB to create
    /// the final key
    pub key_transf_rounds: u32,
}

impl V1Header {
    /// Use this to create a new empty header
    pub fn new() -> V1Header {
        V1Header { signature1:        0,
                   signature2:        0,
                   enc_flag:          0,
                   version:           0,
                   final_randomseed:  vec![],
                   iv:                vec![],
                   num_groups:        0,
                   num_entries:       0,
                   contents_hash:     vec![],
                   transf_randomseed: vec![],
                   key_transf_rounds: 0,
        }
    }

    /// Use this to read the header in. path is the filepath of the database
    pub fn read_header(&mut self, path: String) -> Result<(), V1KpdbError> {
        let file = try!(File::open(path)
                        .map_err(|_| V1KpdbError::FileErr));
        let mut file_bytes = file.bytes();
        let mut header_bytes: Vec<u8> = vec![];

        let mut counter = 0;
        while counter < 124 {
            match file_bytes.next() {
                Some(s) => header_bytes.push(try!(s
                                                  .map_err(|_| V1KpdbError::ReadErr))),
                None    => return Err(V1KpdbError::ReadErr),
            }
            counter += 1;
        }

        let signature1       = try!(slice_to_u32(&header_bytes[0..4]));
        let signature2       = try!(slice_to_u32(&header_bytes[4..8]));
        let enc_flag         = try!(slice_to_u32(&header_bytes[8..12]));
        let version          = try!(slice_to_u32(&header_bytes[12..16]));
        let mut final_randomseed: Vec<u8> = vec![];
        for i in 16..32 { final_randomseed.push(header_bytes[i]); }
        let mut iv: Vec<u8> = vec![];
        for i in 32..48 { iv.push(header_bytes[i]); }
        let num_groups  = try!(slice_to_u32(&header_bytes[48..52]));
        let num_entries = try!(slice_to_u32(&header_bytes[52..56]));
        let mut contents_hash: Vec<u8> = vec![];
        for i in 56..88 { contents_hash.push(header_bytes[i]); }
        let mut transf_randomseed: Vec<u8> = vec![];
        for i in 88..120 { transf_randomseed.push(header_bytes[i]); }
        let key_transf_rounds = try!(slice_to_u32(&header_bytes[120..124]));

        *self = V1Header { signature1: signature1,
                           signature2: signature2,
                           enc_flag: enc_flag,
                           version: version,
                           final_randomseed: final_randomseed,
                           iv: iv,
                           num_groups: num_groups,
                           num_entries: num_entries,
                           contents_hash: contents_hash,
                           transf_randomseed: transf_randomseed,
                           key_transf_rounds: key_transf_rounds };
        
        try!(V1Header::check_signatures(self));
        try!(V1Header::check_enc_flag(self));
        try!(V1Header::check_version(self));
        Ok(())
    }

    // Checks file signatures
    fn check_signatures(header: &V1Header) -> Result<(), V1KpdbError> {
        if header.signature1 != 0x9AA2D903u32 || header.signature2 != 0xB54BFB65u32 {
            return Err(V1KpdbError::SignatureErr);
        }
        Ok(())
    }

    // Checks encryption flag
    fn check_enc_flag(header: &V1Header) -> Result<(), V1KpdbError> {
        if header.enc_flag & 2 != 2 {
            return Err(V1KpdbError::EncFlagErr);
        }
        Ok(())
    }

    // Checks database version
    fn check_version(header: &V1Header) -> Result<(), V1KpdbError> {
        if header.version != 0x00030002u32 {
            return Err(V1KpdbError::VersionErr)
        }
        Ok(())
    }


}

#[cfg(test)]
mod tests {
    use super::V1Header;

    #[test]
    fn test_read_header() {
        let mut header = V1Header::new();
        assert_eq!(header.read_header("test/test_password.kdb".to_string()).is_ok(), true);

        let _ = header.read_header("test/test_password.kdb".to_string());
        assert_eq!(header.signature1, 0x9AA2D903u32);
        assert_eq!(header.signature2, 0xB54BFB65u32);
        assert_eq!(header.enc_flag & 2, 2);
        assert_eq!(header.version, 0x00030002u32);
        assert_eq!(header.num_groups, 2);
        assert_eq!(header.num_entries, 1);
        assert_eq!(header.key_transf_rounds, 150000);
        assert_eq!(header.final_randomseed[0], 0xB0u8);
        assert_eq!(header.final_randomseed[15], 0xE1u8);
        assert_eq!(header.iv[0], 0x15u8);
        assert_eq!(header.iv[15], 0xE5u8);
        assert_eq!(header.contents_hash[0], 0xCBu8);
        assert_eq!(header.contents_hash[15], 0x4Eu8);
        assert_eq!(header.transf_randomseed[0], 0x69u8);
        assert_eq!(header.transf_randomseed[15], 0x9Fu8);
    }
}
