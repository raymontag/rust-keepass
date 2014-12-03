use super::sec_str::SecureString;
use libc::c_void;
use openssl::crypto::hash::{Hasher, HashType};
use openssl::crypto::symm;
use std::io::{File, Open, Read, IoResult, SeekStyle};
use std::ptr;
use std::str;

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
    groups: Vec<Box<V1Group>>,
    // entries:
    // root_group:
}

pub struct V1Group {
    id:          u32, 
    title:       String,
    image:       u32,
    level:       u16,
    creation:    Tm,
    last_mod:    Tm,
    last_access: Tm,
    expire:      Tm,
    flags:       u32,
    parent:      Box<Option<V1Group>>,
    children:    Vec<Box<V1Group>>,
    //entries: Vec<V1Entry>,
    //db: Box<Option<V1Kpdb>>,
}

pub struct Tm {
    year:   i32,
    month:  i32,
    day:    i32,
    hour:   i32,
    minute: i32,
    second: i32,
}

pub enum V1KpdbError {
    FileErr,
    ReadErr,
    SignatureErr,
    EncFlagErr,
    VersionErr,
    DecryptErr,
    HashErr,
    ConvertErr,
    OffsetErr,
}

fn slice_to_u16 (slice: &[u8]) -> Result<u16, V1KpdbError> {
    if slice.len() < 2 {
        return Err(V1KpdbError::ConvertErr);
    }

    let value = slice[1] as u16 << 8;
    Ok(value | slice[0] as u16)
}

fn slice_to_u32 (slice: &[u8]) -> Result<u32, V1KpdbError> {
    if slice.len() < 4 {
        return Err(V1KpdbError::ConvertErr);
    }
    
    let mut value = slice[3] as u32 << 24;
    value |= slice[2] as u32 << 16;
    value |= slice[1] as u32 << 8;
    Ok(value | slice[0] as u32)
}

impl V1Kpdb {
    pub fn new(path: String, password: String, keyfile: String) -> Result<V1Kpdb, V1KpdbError> {
        let header = try!(V1Kpdb::read_header(path.clone()));
        let mut password = SecureString::new(password);
        let decrypted_database = try!(V1Kpdb::decrypt_database(path.clone(), &mut password, &header));
        let groups = try!(V1Kpdb::parse_groups(&header, &decrypted_database));
        Ok(V1Kpdb { path: path, password: password, keyfile: keyfile, header: header, groups: groups})
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

    fn decrypt_database(path: String, password: &mut SecureString, header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let mut file = try!(File::open_mode(&Path::new(path), Open, Read).map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(124i64, SeekStyle::SeekSet).map_err(|_| V1KpdbError::FileErr));
        let crypted_database = try!(file.read_to_end().map_err(|_| V1KpdbError::ReadErr));

        let masterkey = V1Kpdb::get_passwordkey(password);
        let finalkey = V1Kpdb::transform_key(masterkey, header);
        let decrypted_database = V1Kpdb::decrypt_it(finalkey, crypted_database, header);


        try!(V1Kpdb::check_decryption_success(header, &decrypted_database));
        try!(V1Kpdb::check_content_hash(header, &decrypted_database));

        Ok(decrypted_database)
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

    fn transform_key(mut masterkey: Vec<u8>, header: &V1Header) -> Vec<u8> {
        let crypter = symm::Crypter::new(symm::Type::AES_256_ECB);
        crypter.init(symm::Mode::Encrypt, header.transf_randomseed.as_slice(), vec![]);
        for _ in range(0u32, header.key_transf_rounds) {
            masterkey = crypter.update(masterkey.as_slice());
        }
        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(masterkey.as_slice());
        masterkey = hasher.finalize();

        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(header.final_randomseed.as_slice());
        hasher.update(masterkey.as_slice());

        unsafe { ptr::zero_memory(masterkey.as_ptr() as *mut c_void, masterkey.len()) };

        hasher.finalize()
    }

    fn decrypt_it(finalkey: Vec<u8>, crypted_database: Vec<u8>, header: &V1Header) -> Vec<u8> {
        let db_tmp = symm::decrypt(symm::Type::AES_256_CBC, finalkey.as_slice(), header.iv.clone(), 
                                   crypted_database.as_slice());

        unsafe { ptr::zero_memory(finalkey.as_ptr() as *mut c_void, finalkey.len()) };

        let padding = db_tmp[db_tmp.len() - 1] as uint;
        let length = db_tmp.len(); 
        let mut db_iter = db_tmp.into_iter().take(length - padding);
        Vec::from_fn(length - padding, |_| db_iter.next().unwrap())
    }

    fn check_decryption_success(header: &V1Header, decrypted_content: &Vec<u8>) -> Result<(), V1KpdbError> {
        if (decrypted_content.len() > 2147483446) || (decrypted_content.len() == 0 && header.num_groups > 0) {
            return Err(V1KpdbError::DecryptErr);
        }
        Ok(())
    }
    
    fn check_content_hash(header: &V1Header, decrypted_content: &Vec<u8>) -> Result<(), V1KpdbError> {
        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(decrypted_content.as_slice());
        if hasher.finalize() != header.contents_hash {
            return Err(V1KpdbError::HashErr);
        }
        Ok(())
    }

    fn parse_groups(header: &V1Header, decrypted_database: &Vec<u8>) -> Result<Vec<Box<V1Group>>, V1KpdbError> {
        let mut pos: uint = 0;
        let mut group_number: u32 = 0;
        let mut levels: Vec<u16> = vec![];
        let mut cur_group = box V1Group::new();
        let mut groups: Vec<Box<V1Group>> = vec![];
        
        let mut field_type: u16;
        let mut field_size: u32;

        while group_number < header.num_groups {
            field_type = try!(slice_to_u16(decrypted_database.slice(pos, pos + 2)));
            pos += 2;

            if pos >= decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(decrypted_database.slice(pos, pos + 4)));
            pos += 4;

            if pos >= decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = V1Kpdb::read_group_field(&mut cur_group, &mut levels, field_type, field_size, 
                                         decrypted_database, pos);

            if field_type == 0xFFFF {
                groups.push(cur_group);
                cur_group = box V1Group::new();
                group_number += 1;
            }

            pos += field_size as uint;
        }

        Ok(groups)
    }

    fn read_group_field(group: &mut Box<V1Group>, levels: &mut Vec<u16>, field_type: u16, field_size: u32,
                        decrypted_database: &Vec<u8>, pos: uint) -> Result<(), V1KpdbError> {
        let db_slice = if field_type == 0x0002 {
            decrypted_database.slice(pos, pos + (field_size - 1) as uint)
        } else {
            decrypted_database.slice(pos, pos + field_size as uint)
        };

        match field_type {
            0x0001 => group.id = try!(slice_to_u32(db_slice)),
            0x0002 => group.title = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x0003 => group.creation = V1Kpdb::get_date(db_slice),
            0x0004 => group.last_mod = V1Kpdb::get_date(db_slice),
            0x0005 => group.last_access = V1Kpdb::get_date(db_slice),
            0x0006 => group.expire = V1Kpdb::get_date(db_slice),
            0x0007 => group.image = try!(slice_to_u32(db_slice)),
            0x0008 => { group.level = try!(slice_to_u16(db_slice)); 
                        levels.push(group.level) },
            0x0009 => group.flags = try!(slice_to_u32(db_slice)),
            _ => (),
        }

        Ok(())
    }

    fn get_date(date_bytes: &[u8]) -> Tm {
        let dw1 = date_bytes[0] as i32;
        let dw2 = date_bytes[1] as i32;
        let dw3 = date_bytes[2] as i32;
        let dw4 = date_bytes[3] as i32;
        let dw5 = date_bytes[4] as i32;

        let year = (dw1 << 6) | (dw2 >> 2);
        let month = ((dw2 & 0x03) << 2) | (dw3 >> 6);
        let day = (dw3 >> 1) & 0x1F;
        let hour = ((dw3 & 0x01) << 4) | (dw4 >> 4);
        let minute = ((dw4 & 0x0F) << 2) | (dw5 >> 6);
        let second = dw5 & 0x3F;

        Tm { year: year, month: month, day: day, hour: hour, minute: minute, second: second }
    }
}

impl V1Group {
    pub fn new() -> V1Group {
        V1Group { id:          0, 
                  title:       "".to_string(),
                  image:       0,
                  level:       0,
                  creation:    Tm::new(),
                  last_mod:    Tm::new(),
                  last_access: Tm::new(),
                  expire:      Tm::new(),
                  flags:       0,
                  parent:      box None,
                  children:    vec![],
                  //entries: Vec<V1Entry>,
                  //db: box None,
        }
    }
}

impl Tm {
    pub fn new() -> Tm {
        Tm { year:   0,
             month:  0,
             day:    0,
             hour:   0,
             minute: 0,
             second: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::V1Kpdb;
    use super::super::sec_str::SecureString;

    #[test]
    fn test_new() {
        let mut db = V1Kpdb::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string()).ok().unwrap();
        assert_eq!(db.path.as_slice(), "test/test_password.kdb");
        assert_eq!(db.password.string.as_slice(), "\0\0\0\0");
        assert_eq!(db.keyfile.as_slice(), "");

        db.password.unlock();
        assert_eq!(db.password.string.as_slice(), "test");

        assert_eq!(V1Kpdb::new("test/test_password.kdb".to_string(), "tes".to_string(), "".to_string()).is_err(), true);
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

    #[test]
    fn test_passwordkey() {
        let testkey = vec![0x04, 0xE7, 0x22, 0xF6,
                           0x17, 0x1D, 0x5A, 0x4D,
                           0xE9, 0xBE, 0x7D, 0x36,
                           0x74, 0xB1, 0x5F, 0x83,
                           0xA7, 0xD4, 0x22, 0x67,
                           0xAF, 0x38, 0x24, 0x05,
                           0xDA, 0x9A, 0xA6, 0x09,
                           0x3E, 0x63, 0xC8, 0x70];

        let header = V1Kpdb::read_header("test/test_password.kdb".to_string()).ok().unwrap();
        let mut sec_str = SecureString::new("test".to_string());
        let masterkey = V1Kpdb::get_passwordkey(&mut sec_str);
        let finalkey = V1Kpdb::transform_key(masterkey, &header);
        assert_eq!(finalkey, testkey);
    }

    #[test]
    fn test_decrypt_it() {
        let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00,
                                          0x00, 0x00, 0x01, 0x00,
                                          0x00, 0x00, 0x02, 0x00,
                                          0x09, 0x00, 0x00, 0x00];
        let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00,
                                          0x00, 0x1F, 0x7C, 0xB5,
                                          0x7E, 0xFB, 0xFF, 0xFF,
                                          0x00, 0x00, 0x00, 0x00];

        let header = V1Kpdb::read_header("test/test_password.kdb".to_string()).ok().unwrap();
        let mut sec_str = SecureString::new("test".to_string());
        let db_tmp = V1Kpdb::decrypt_database("test/test_password.kdb".to_string(), &mut sec_str, &header).ok().unwrap();        
        let db_len = db_tmp.len();
        let db_clone = db_tmp.clone();

        let mut db_iter = db_tmp.into_iter();
        let db_iter2 = db_clone.into_iter();
        let mut db_iter3 = db_iter2.skip(db_len - 16);
        
        let test1 = Vec::from_fn(16, |_| db_iter.next().unwrap());
        let test2 = Vec::from_fn(16, |_| db_iter3.next().unwrap());

        assert_eq!(test_content1, test1);
        assert_eq!(test_content2, test2);
    }

    #[test]
    fn test_parse_groups () {
        let db = V1Kpdb::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string()).ok().unwrap();

        assert_eq!(db.groups[0].id, 1);
        assert_eq!(db.groups[0].title.as_slice(), "Internet");
        assert_eq!(db.groups[0].image, 1);
        assert_eq!(db.groups[0].level, 0);
        assert_eq!(db.groups[0].creation.year, 0);
        assert_eq!(db.groups[0].creation.month, 0);
        assert_eq!(db.groups[0].creation.day, 0);

        assert_eq!(db.groups[1].id, 2);
        assert_eq!(db.groups[1].title.as_slice(), "test");
        assert_eq!(db.groups[1].image, 1);
        assert_eq!(db.groups[1].level, 0);
        assert_eq!(db.groups[1].creation.year, 2014);
        assert_eq!(db.groups[1].creation.month, 2);
        assert_eq!(db.groups[1].creation.day, 26);

    }
}
