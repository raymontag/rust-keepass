use super::sec_str::SecureString;
use std::io::{File, Open, Read, IoResult};

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

pub struct V1KPDB {
    path:     String,
    password: SecureString,
    keyfile:  String,
    header:   V1Header,
    // groups:
    // entries:
    // root_group:
}

impl V1KPDB {
    pub fn new(path: String, password: String, keyfile: String) -> V1KPDB{
        V1KPDB { path: path.clone(), password: SecureString::new(password), keyfile: keyfile, header: V1KPDB::read_header(path) }
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

    fn read_header(path: String) -> V1Header {
        let file = File::open_mode(&Path::new(path), Open, Read).ok().expect("Couldn't open database");
        V1KPDB::read_header_(file).ok().expect("Couldn't read header. Maybe the file is to small (should be more then 124B)?")
    }
}

#[cfg(test)]
mod tests {
    use super::V1KPDB;

    #[test]
    fn test_new() {
        let mut db = V1KPDB::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string());
        assert_eq!(db.path.as_slice(), "test/test_password.kdb");
        assert_eq!(db.password.string.as_slice(), "\0\0\0\0");
        assert_eq!(db.keyfile.as_slice(), "");

        db.password.unlock();
        assert_eq!(db.password.string.as_slice(), "test")
    }

    #[test]
    fn test_read_header() {
        let header = V1KPDB::read_header("test/test_password.kdb".to_string());
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
