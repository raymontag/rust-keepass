use std::io::{File, Open, Read, IoResult, SeekStyle};

use super::v1error::V1KpdbError;

pub struct V1Header {
    pub signature1:        u32,
    pub signature2:        u32,
    pub enc_flag:          u32,
    pub version:           u32,
    pub final_randomseed:  Vec<u8>,
    pub iv:                Vec<u8>,
    pub num_groups:        u32,
    pub num_entries:       u32,
    pub contents_hash:     Vec<u8>,
    pub transf_randomseed: Vec<u8>,
    pub key_transf_rounds: u32,
}

impl V1Header {
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

    fn read_header_(mut file: File) -> IoResult<V1Header> {
        let signature1 = try!(file.read_le_u32());
        let signature2 = try!(file.read_le_u32());
        let enc_flag = try!(file.read_le_u32());
        let version = try!(file.read_le_u32());
        let final_randomseed = try!(file.read_exact(16us));
        let iv = try!(file.read_exact(16us));
        let num_groups = try!(file.read_le_u32());
        let num_entries = try!(file.read_le_u32());
        let contents_hash = try!(file.read_exact(32us));
        let transf_randomseed = try!(file.read_exact(32us));
        let key_transf_rounds = try!(file.read_le_u32());

        Ok(V1Header { signature1: signature1,
                      signature2: signature2,
                      enc_flag: enc_flag,
                      version: version,
                      final_randomseed: final_randomseed,
                      iv: iv,
                      num_groups: num_groups,
                      num_entries: num_entries,
                      contents_hash: contents_hash,
                      transf_randomseed: transf_randomseed,
                      key_transf_rounds: key_transf_rounds })
    }

    pub fn read_header(&mut self, path: String) -> Result<(), V1KpdbError> {
        let file = try!(File::open_mode(&Path::new(path), Open, Read).map_err(|_| V1KpdbError::FileErr));
        *self = try!(V1Header::read_header_(file).map_err(|_| V1KpdbError::ReadErr));
        
        try!(V1Header::check_signatures(self));
        try!(V1Header::check_enc_flag(self));
        try!(V1Header::check_version(self));
        Ok(())
    }

    fn check_signatures(header: &V1Header) -> Result<(), V1KpdbError> {
        if header.signature1 != 0x9AA2D903u32 || header.signature2 != 0xB54BFB65u32 {
            return Err(V1KpdbError::SignatureErr);
        }
        Ok(())
    }

    fn check_enc_flag(header: &V1Header) -> Result<(), V1KpdbError> {
        if header.enc_flag & 2 != 2 {
            return Err(V1KpdbError::EncFlagErr);
        }
        Ok(())
    }

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
