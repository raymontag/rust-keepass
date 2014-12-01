use super::sec_str::SecureString;
use openssl::crypto::hash::{Hasher, HashType};
use openssl::crypto::symm;
use std::io::{File, Open, Read, IoResult, SeekStyle};

struct V1Header {
    signature1:        u32,
    signature2:        u32,
    enc_flag:          u32,
    version:           u32,
    final_randomseed:  Vec<u8>,
    iv:                Vec<u8>,
    num_groups:        u32,
    num_entries:       u32,
    contents_hash:     Vec<u8>,
    transf_randomseed: Vec<u8>,
    key_transf_rounds: u32,
}

pub struct V1Kpdb {
    path:     String,
    password: SecureString,
    keyfile:  String,
    header:   V1Header,
    // groups:
    // entries:
    // root_group:
}

pub enum V1KpdbError {
    FileErr,
    ReadErr,
    SignatureErr,
    EncFlagErr,
    VersionErr,
}

impl V1Kpdb {
    pub fn new(path: String, password: String, keyfile: String) -> Result<V1Kpdb, V1KpdbError> {
        let header = try!(V1Kpdb::read_header(path.clone()));
        let mut password = SecureString::new(password);
        Ok(V1Kpdb { path: path, password: password, keyfile: keyfile, header: header })
    }

    fn read_header_(mut file: File) -> IoResult<V1Header> {
        let signature1 = try!(file.read_le_u32());
        let signature2 = try!(file.read_le_u32());
        let enc_flag = try!(file.read_le_u32());
        let version = try!(file.read_le_u32());
        let final_randomseed = try!(file.read_exact(16u));
        let iv = try!(file.read_exact(16u));
        let num_groups = try!(file.read_le_u32());
        let num_entries = try!(file.read_le_u32());
        let contents_hash = try!(file.read_exact(32u));
        let transf_randomseed = try!(file.read_exact(32u));
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

    fn read_header(path: String) -> Result<V1Header, V1KpdbError> {
        let file = try!(File::open_mode(&Path::new(path), Open, Read).map_err(|_| V1KpdbError::FileErr));
        let header = try!(V1Kpdb::read_header_(file).map_err(|_| V1KpdbError::ReadErr));
        
        try!(V1Kpdb::check_signatures(&header));
        try!(V1Kpdb::check_enc_flag(&header));
        try!(V1Kpdb::check_version(&header));
        Ok(header)
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

    fn decrypt_database(path: String, password: &mut SecureString) -> Result<(), V1KpdbError> {
        let mut file = try!(File::open_mode(&Path::new(path), Open, Read).map_err(|_| V1KpdbError::FileErr));
        file.seek(124i64, SeekStyle::SeekSet);
        let decrypted_database = try!(file.read_to_end().map_err(|_| V1KpdbError::ReadErr));

        let masterkey = V1Kpdb::get_passwordkey(password);

        Ok(())
    }

    fn get_passwordkey(password: &mut SecureString) -> Vec<u8> {
        // password.string.as_bytes() is secure as just a reference is returned
        password.unlock();
        let password_string = password.string.as_bytes();

        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(password_string);
        password.delete();

        hasher.finalize()
    }

    fn transform_key(masterkey: Vec<u8>) {
        
    }
}

#[cfg(test)]
mod tests {
    use super::V1Kpdb;

    #[test]
    fn test_new() {
        let mut db = V1Kpdb::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string()).ok().unwrap();
        assert_eq!(db.path.as_slice(), "test/test_password.kdb");
        assert_eq!(db.password.string.as_slice(), "\0\0\0\0");
        assert_eq!(db.keyfile.as_slice(), "");

        db.password.unlock();
        assert_eq!(db.password.string.as_slice(), "test")
    }

    #[test]
    fn test_read_header() {
        let header = V1Kpdb::read_header("test/test_password.kdb".to_string()).ok().unwrap();
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
