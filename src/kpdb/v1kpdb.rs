use libc::c_void;
use std::cell::{RefCell, RefMut};
use std::io::{File, Open, Read, IoResult, SeekStyle};
use std::ptr;
use std::rc::Rc;
use std::str;

use openssl::crypto::hash::{Hasher, HashType};
use openssl::crypto::symm;

use super::v1error::V1KpdbError;
use super::v1group::V1Group;
use super::v1entry::V1Entry;
use super::v1header::V1Header;
use super::tm::Tm;
use super::super::sec_str::SecureString;

pub struct V1Kpdb {
    pub path:     String,
    pub password: SecureString,
    pub keyfile:  String,
    pub header:   V1Header,
    pub groups: Vec<Rc<RefCell<V1Group>>>,
    pub entries: Vec<Box<V1Entry>>,
    pub root_group: Rc<RefCell<V1Group>>,
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
    pub fn new(path: String, password: String, keyfile: String) -> V1Kpdb {
        V1Kpdb { path: path, password: SecureString::new(password), keyfile: keyfile, header: V1Header::new(), 
                 groups: vec![], entries: vec![], root_group: Rc::new(RefCell::new(V1Group::new())) }
    }

    pub fn load(&mut self) -> Result<(), V1KpdbError> {
        try!(self.header.read_header(self.path.clone()));
        let decrypted_database = try!(V1Kpdb::decrypt_database(self.path.clone(), &mut self.password, &self.header));

        let mut pos: uint = 0;
        let (groups, levels) = try!(V1Kpdb::parse_groups(&self.header, &decrypted_database, &mut pos));
        self.groups = groups;
        self.entries = try!(V1Kpdb::parse_entries(&self.header, &decrypted_database, &pos));
        try!(V1Kpdb::create_group_tree(self, levels));
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

    fn parse_groups(header: &V1Header, decrypted_database: &Vec<u8>, remembered_pos: &mut uint) -> Result<(Vec<Rc<RefCell<V1Group>>>, Vec<u16>), V1KpdbError> {
        let mut pos: uint = 0;
        let mut group_number: u32 = 0;
        let mut levels: Vec<u16> = vec![];
        let mut cur_group = Rc::new(RefCell::new(V1Group::new()));
        let mut groups: Vec<Rc<RefCell<V1Group>>> = vec![];
        
        let mut field_type: u16;
        let mut field_size: u32;

        while group_number < header.num_groups {
            field_type = try!(slice_to_u16(decrypted_database.slice(pos, pos + 2)));
            pos += 2;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(decrypted_database.slice(pos, pos + 4)));
            pos += 4;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = V1Kpdb::read_group_field(cur_group.borrow_mut(), field_type, field_size, 
                                             decrypted_database, pos);

            
            if field_type == 0x0008 {
                levels.push(cur_group.borrow().level);
            } else if field_type == 0xFFFF {
                groups.push(cur_group);
                group_number += 1;
                if group_number == header.num_groups {
                    break;
                };
                cur_group = Rc::new(RefCell::new(V1Group::new()));
            }

            pos += field_size as uint;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }
        
        *remembered_pos = pos;
        Ok((groups, levels))
    }

    fn parse_entries(header: &V1Header, decrypted_database: &Vec<u8>, remembered_pos: &uint) -> Result<Vec<Box<V1Entry>>, V1KpdbError> {
        let mut pos = *remembered_pos;
        let mut entry_number: u32 = 0;
        let mut cur_entry = box V1Entry::new();
        let mut entries: Vec<Box<V1Entry>> = vec![];
        
        let mut field_type: u16;
        let mut field_size: u32;

        while entry_number < header.num_entries {
            field_type = try!(slice_to_u16(decrypted_database.slice(pos, pos + 2)));
            pos += 2;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(decrypted_database.slice(pos, pos + 4)));
            pos += 4;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = V1Kpdb::read_entry_field(&mut cur_entry, field_type, field_size, 
                                             decrypted_database, pos);

            if field_type == 0xFFFF {
                entries.push(cur_entry);
                entry_number += 1;
                if entry_number == header.num_entries {
                    break;
                };
                cur_entry = box V1Entry::new() 
            }

            pos += field_size as uint;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }

        Ok(entries)
    }

    fn read_group_field(mut group: RefMut<V1Group>, field_type: u16, field_size: u32,
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
            0x0008 => group.level = try!(slice_to_u16(db_slice)),
            0x0009 => group.flags = try!(slice_to_u32(db_slice)),
            _ => (),
        }

        Ok(())
    }

    fn read_entry_field(entry: &mut Box<V1Entry>, field_type: u16, field_size: u32,
                        decrypted_database: &Vec<u8>, pos: uint) -> Result<(), V1KpdbError> {
        let db_slice = match field_type {
            0x0004 ... 0x0008 | 0x000D => decrypted_database.slice(pos, pos + (field_size - 1) as uint),
            _ => decrypted_database.slice(pos, pos + field_size as uint),
        };

        match field_type {
            0x0001 => entry.uuid = Vec::from_fn(field_size as uint , |i| db_slice[i]),
            0x0002 => entry.group_id = try!(slice_to_u32(db_slice)),
            0x0003 => entry.image = try!(slice_to_u32(db_slice)),
            0x0004 => entry.title = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x0005 => entry.url = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x0006 => entry.username = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x0007 => entry.password = SecureString::new(str::from_utf8(db_slice).unwrap().to_string()),
            0x0008 => entry.comment = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x0009 => entry.creation = V1Kpdb::get_date(db_slice),
            0x000A => entry.last_mod = V1Kpdb::get_date(db_slice),
            0x000B => entry.last_access = V1Kpdb::get_date(db_slice),
            0x000C => entry.expire = V1Kpdb::get_date(db_slice),
            0x000D => entry.binary_desc = str::from_utf8(db_slice).unwrap_or("").to_string(),
            0x000E => entry.binary = Vec::from_fn(field_size as uint, |i| db_slice[i]),
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

    fn create_group_tree(db: &mut V1Kpdb, levels: Vec<u16>) -> Result<(), V1KpdbError> {
        if levels[0] != 0 {
            return Err(V1KpdbError::TreeErr);
        }
        
        for i in range(0, db.groups.len()) {
            if levels[i] == 0 {
                db.groups[i].borrow_mut().parent = Some(db.root_group.clone());
                db.root_group.borrow_mut().children.push(db.groups[i].clone().downgrade());
                continue;
            }

            let mut j = i - 1;
            loop {
                if levels[j] < levels[i] {
                    if levels[i] - levels[j] != 1 {
                        return Err(V1KpdbError::TreeErr);
                    }
                    db.groups[i].borrow_mut().parent = Some(db.groups[j].clone());
                    db.groups[j].borrow_mut().children.push(db.groups[i].clone().downgrade());
                    break;
                }
                if j == 0 {
                    return Err(V1KpdbError::TreeErr);
                }
                j -= 1;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::V1Kpdb;
    use super::super::v1header::V1Header;
    use super::super::super::sec_str::SecureString;

    #[test]
    fn test_new() {
        assert_eq!(V1Kpdb::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string()).load().is_ok(), true);

        let mut db = V1Kpdb::new("test/test_password.kdb".to_string(), "test".to_string(), "".to_string());
        let _ = db.load();
        assert_eq!(db.path.as_slice(), "test/test_password.kdb");
        assert_eq!(db.password.string.as_slice(), "\0\0\0\0");
        assert_eq!(db.keyfile.as_slice(), "");

        db.password.unlock();
        assert_eq!(db.password.string.as_slice(), "test");

        assert_eq!(V1Kpdb::new("test/test_password.kdb".to_string(), "tes".to_string(), "".to_string()).load().is_err(), true);
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

        let mut header = V1Header::new();
        let _ = header.read_header("test/test_password.kdb".to_string());
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

        let mut header = V1Header::new();
        let _ = header.read_header("test/test_password.kdb".to_string());
        let mut sec_str = SecureString::new("test".to_string());

        assert_eq!(V1Kpdb::decrypt_database("test/test_password.kdb".to_string(), &mut sec_str, &header).is_ok(), true);

        let db_tmp = V1Kpdb::decrypt_database("test/test_password.kdb".to_string(), &mut sec_str, &header).ok().unwrap();        
        let db_len = db_tmp.len();
        let db_clone = db_tmp.clone();
        // let test_clone = db_tmp.clone();

        let mut db_iter = db_tmp.into_iter();
        let db_iter2 = db_clone.into_iter();
        let mut db_iter3 = db_iter2.skip(db_len - 16);
        
        let test1 = Vec::from_fn(16, |_| db_iter.next().unwrap());
        let test2 = Vec::from_fn(16, |_| db_iter3.next().unwrap());

        // for i in test_clone.into_iter() {
        //     print!("{:x} ", i);
        // }

        assert_eq!(test_content1, test1);
        assert_eq!(test_content2, test2);
    }

    #[test]
    fn test_parse_groups () {
        let mut header = V1Header::new();
        let _ = header.read_header("test/test_password.kdb".to_string());
        let mut sec_str = SecureString::new("test".to_string());
        let decrypted_database = V1Kpdb::decrypt_database("test/test_password.kdb".to_string(), &mut sec_str, &header).ok().unwrap();        

        assert_eq!(V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0u).is_ok(), true);

        let (groups, _) = V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0u).ok().unwrap();

        assert_eq!(groups[0].borrow().id, 1);
        assert_eq!(groups[0].borrow().title.as_slice(), "Internet");
        assert_eq!(groups[0].borrow().image, 1);
        assert_eq!(groups[0].borrow().level, 0);
        assert_eq!(groups[0].borrow().creation.year, 0);
        assert_eq!(groups[0].borrow().creation.month, 0);
        assert_eq!(groups[0].borrow().creation.day, 0);

        assert_eq!(groups[1].borrow().id, 2);
        assert_eq!(groups[1].borrow().title.as_slice(), "test");
        assert_eq!(groups[1].borrow().image, 1);
        assert_eq!(groups[1].borrow().level, 0);
        assert_eq!(groups[1].borrow().creation.year, 2014);
        assert_eq!(groups[1].borrow().creation.month, 2);
        assert_eq!(groups[1].borrow().creation.day, 26);
    }

    #[test]
    fn test_parse_entries () {
        let uuid: Vec<u8> = vec![0x0c, 0x31, 0xac, 0x94, 0x23, 0x47, 0x66, 0x36, 
                                      0xb8, 0xc0, 0x42, 0x81, 0x5e, 0x5a, 0x14, 0x60];

        let mut header = V1Header::new();
        let _ = header.read_header("test/test_password.kdb".to_string());
        let mut sec_str = SecureString::new("test".to_string());
        let decrypted_database = V1Kpdb::decrypt_database("test/test_password.kdb".to_string(), &mut sec_str, &header).ok().unwrap();        

        assert_eq!(V1Kpdb::parse_entries(&header, &decrypted_database, &mut 138u).is_ok(), true);

        let mut entries = V1Kpdb::parse_entries(&header, &decrypted_database, &mut 138u).ok().unwrap();

        entries[0].password.unlock();

        assert_eq!(entries[0].uuid, uuid);
        assert_eq!(entries[0].title.as_slice(), "foo");
        assert_eq!(entries[0].url.as_slice(), "foo");
        assert_eq!(entries[0].username.as_slice(), "foo");
        assert_eq!(entries[0].password.string.as_slice(), "DLE\"H<JZ|E");
        assert_eq!(entries[0].image, 1);
        assert_eq!(entries[0].group_id, 1);
        assert_eq!(entries[0].creation.year, 2014);
        assert_eq!(entries[0].creation.month, 2);
        assert_eq!(entries[0].creation.day, 26);
    }

    #[test]
    fn test_create_group_tree() {
        let mut db = V1Kpdb::new("test/test_parsing.kdb".to_string(), "test".to_string(), "".to_string());
        
        let mut header = V1Header::new();
        let _ = header.read_header("test/test_parsing.kdb".to_string());
        let mut sec_str = SecureString::new("test".to_string());
        let decrypted_database = V1Kpdb::decrypt_database("test/test_parsing.kdb".to_string(), &mut sec_str, &header).ok().unwrap();

        assert_eq!(V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0u).is_ok(), true);
        let (groups, levels) = V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0u).ok().unwrap();
        db.groups = groups;

        assert_eq!(V1Kpdb::create_group_tree(&mut db, levels).is_ok(), true);

        assert_eq!(db.groups[1].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "Internet");
        assert_eq!(db.groups[2].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "Internet");
        assert_eq!(db.groups[2].borrow_mut().children[0].upgrade().unwrap().borrow().title.as_slice(), "22");
        assert_eq!(db.groups[2].borrow_mut().children[1].upgrade().unwrap().borrow().title.as_slice(), "21");
        assert_eq!(db.groups[3].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "11");
        assert_eq!(db.groups[4].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "11");
        assert_eq!(db.groups[4].borrow_mut().children[0].upgrade().unwrap().borrow().title.as_slice(), "32");
        assert_eq!(db.groups[4].borrow_mut().children[1].upgrade().unwrap().borrow().title.as_slice(), "31");
        assert_eq!(db.groups[5].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "21");
        assert_eq!(db.groups[6].borrow_mut().parent.as_mut().unwrap().borrow().title.as_slice(), "21");
    }
}
