use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use std::cell::{RefCell, RefMut};
use std::io::{File, Open, Read, SeekStyle};
use std::io::IoErrorKind::EndOfFile;
use std::ptr;
use std::rc::Rc;
use std::str;

use openssl::crypto::hash::{Hasher, HashType};
use openssl::crypto::symm;
use rustc_serialize::hex::FromHex;

use super::v1error::V1KpdbError;
use super::v1group::V1Group;
use super::v1entry::V1Entry;
use super::v1header::V1Header;
use super::tm::Tm;
use super::super::sec_str::SecureString;

#[doc = "
V1Kpdb implements a KeePass v1.x database. Some notes on the file format:

* Database is encrypted with AES (Twofish currently not supported by this
  module) with a password and/or a keyfile.
* Database holds entries which describes the credentials (username, password
  URL...) and are sorted in groups
* The groups themselves can hold subgroups
* Entries have titles for better identification by the user and expiration
  dates to remind that the password should be changed after some period

TODO:

* saving
* editing
* get rid of unwrap and use more pattern matching
"]
pub struct V1Kpdb {
    /// Filepath of the database
    pub path:     String,
    /// Password of the database
    pub password: Option<SecureString>,
    /// Filepath of the keyfile
    pub keyfile:  Option<SecureString>,
    /// Holds the header. Normally you don't need
    /// to manipulate this yourself
    pub header:   V1Header,
    /// The groups which hold the entries
    pub groups: Vec<Rc<RefCell<V1Group>>>,
    /// The entries of the whole database
    pub entries: Vec<Rc<RefCell<V1Entry>>>,
    /// A group which holds all groups of level 0
    /// as a subgroup (all groups which are not a
    /// subgroup of another group )
    pub root_group: Rc<RefCell<V1Group>>,
} 

// Needed to parse the decrypted database
fn slice_to_u16 (slice: &[u8]) -> Result<u16, V1KpdbError> {
    if slice.len() < 2 {
        return Err(V1KpdbError::ConvertErr);
    }

    let value = (slice[1] as u16) << 8;
    Ok(value | slice[0] as u16)
}

fn slice_to_u32 (slice: &[u8]) -> Result<u32, V1KpdbError> {
    if slice.len() < 4 {
        return Err(V1KpdbError::ConvertErr);
    }
    
    let mut value = (slice[3] as u32) << 24;
    value |= (slice[2] as u32) << 16;
    value |= (slice[1] as u32) << 8;
    Ok(value | slice[0] as u32)
}

impl V1Kpdb {
    /// Call this to create a new database instance. You have to call load
    /// to start decrypting and parsing of an existing database!
    /// path is the filepath of the database, password is the database password
    /// and keyfile is the filepath to the keyfile.
    /// password should already lie on the heap as a String type and not &str
    /// as it will be encrypted automatically and otherwise the plaintext
    /// would lie in the memory though
    pub fn new(path: String,
               password: Option<String>,
               keyfile: Option<String>) -> Result<V1Kpdb, V1KpdbError> {
        // Password and/or keyfile needed but at least one of both
        if password.is_none() && keyfile.is_none() {
            return Err(V1KpdbError::PassErr);
        }
        let sec_password = match password {
            Some(s) => Some(SecureString::new(s)),
            None => None,
        };
        let sec_keyfile = match keyfile {
            Some(s) => Some(SecureString::new(s)),
            None => None,
        };

        Ok(V1Kpdb { path: path, password: sec_password,
                    keyfile: sec_keyfile, header: V1Header::new(),
                    groups: vec![], entries: vec![],
                    root_group: Rc::new(RefCell::new(V1Group::new())) })
    }

    /// Decrypt and parse the database.
    pub fn load(&mut self) -> Result<(), V1KpdbError> {
        // First read header and decrypt the database
        try!(self.header.read_header(self.path.clone()));
        let decrypted_database = try!(V1Kpdb::decrypt_database(self.path.clone(),
                                                               &mut self.password,
                                                               &mut self.keyfile,
                                                               &self.header));
        // Next parse groups and entries.
        // pos is needed to remember position after group parsing
        let mut pos: usize = 0;
        let (groups, levels) = try!(V1Kpdb::parse_groups(&self.header,
                                                         &decrypted_database,
                                                         &mut pos));
        self.groups = groups;
        self.entries = try!(V1Kpdb::parse_entries(&self.header,
                                                  &decrypted_database,
                                                  &pos));
        
        // Zero out raw data as it's not needed anymore
        unsafe { ptr::zero_memory(decrypted_database.as_ptr() as *mut c_void,
                                  decrypted_database.len());
                 mman::munlock(decrypted_database.as_ptr() as *const c_void,
                               decrypted_database.len() as size_t); }
        
        // Now create the group tree and sort the entries to their groups
        try!(V1Kpdb::create_group_tree(self, levels));
        Ok(())
    }

    // Decrypt the database and return the raw data as Vec<u8>
    fn decrypt_database(path: String,
                        password: &mut Option<SecureString>,
                        keyfile: &mut Option<SecureString>,
                        header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let mut file = try!(File::open_mode(&Path::new(path), Open, Read)
                            .map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(124i64, SeekStyle::SeekSet)
             .map_err(|_| V1KpdbError::FileErr));
        let crypted_database = try!(file.read_to_end()
                                    .map_err(|_| V1KpdbError::ReadErr));

        // Create the key and decrypt the database finally
        let masterkey = match (password, keyfile) {
            // Only password provided
            (&mut Some(ref mut p), &mut None) => V1Kpdb::get_passwordkey(p),
            // Only keyfile provided            
            (&mut None, &mut Some(ref mut k)) => try!(V1Kpdb::get_keyfilekey(k)),
            // Both provided
            (&mut Some(ref mut p), &mut Some(ref mut k)) => {
                // Get hashed keys...
                let passwordkey = V1Kpdb::get_passwordkey(p);
                unsafe { mman::mlock(passwordkey.as_ptr() as *const c_void,
                                     passwordkey.len() as size_t); } 
                
                let keyfilekey = try!(V1Kpdb::get_keyfilekey(k));
                unsafe { mman::mlock(keyfilekey.as_ptr() as *const c_void,
                                     keyfilekey.len() as size_t); } 

                // ...and hash them together
                let mut hasher = Hasher::new(HashType::SHA256);
                hasher.update(passwordkey.as_slice());
                hasher.update(keyfilekey.as_slice());

                // Zero out unneeded keys
                unsafe { ptr::zero_memory(passwordkey.as_ptr() as *mut c_void,
                                          passwordkey.len());
                         ptr::zero_memory(keyfilekey.as_ptr() as *mut c_void,
                                          keyfilekey.len());
                         mman::munlock(passwordkey.as_ptr() as *const c_void,
                                       passwordkey.len() as size_t);
                         mman::munlock(keyfilekey.as_ptr() as *const c_void,
                                       keyfilekey.len() as size_t); }
                
                hasher.finalize()
            },
            (&mut None, &mut None) => return Err(V1KpdbError::PassErr),
        };
        unsafe { mman::mlock(masterkey.as_ptr() as *const c_void,
                             masterkey.len() as size_t); }
        
        let finalkey = V1Kpdb::transform_key(masterkey, header);
        unsafe { mman::mlock(finalkey.as_ptr() as *const c_void,
                             finalkey.len() as size_t); }
        
        let decrypted_database = V1Kpdb::decrypt_it(finalkey, crypted_database, header);

        try!(V1Kpdb::check_decryption_success(header, &decrypted_database));
        try!(V1Kpdb::check_content_hash(header, &decrypted_database));

        // Prevent swapping of raw data
        unsafe { mman::mlock(decrypted_database.as_ptr() as *const c_void,
                             decrypted_database.len() as size_t); } 
        
        Ok(decrypted_database)
    }

    // Hash the password string to create a decryption key from that
    fn get_passwordkey(password: &mut SecureString) -> Vec<u8> {
        // unlock SecureString
        password.unlock();
        // password.string.as_bytes() is secure as just a reference is returned
        let password_string = password.string.as_bytes();

        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(password_string);
        // Zero out plaintext password
        password.delete();

        hasher.finalize()
    }

    // Get key from keyfile
    fn get_keyfilekey(keyfile: &mut SecureString) -> Result<Vec<u8>, V1KpdbError> {
        //unlock SecureString
        keyfile.unlock();
        // keyfile.string.as_bytes() is secure as just a reference is returned
        let keyfile_path = keyfile.string.as_bytes();
        
        let mut file = try!(File::open_mode(&Path::new(keyfile_path), Open, Read)
                            .map_err(|_| V1KpdbError::FileErr));
        // Zero out plaintext keyfile path
        keyfile.delete();

        try!(file.seek(0i64, SeekStyle::SeekEnd)
             .map_err(|_| V1KpdbError::FileErr));
        let file_size = try!(file.tell().map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(0i64, SeekStyle::SeekSet)
             .map_err(|_| V1KpdbError::FileErr));
        
        if file_size == 32 {
            let mut key: Vec<u8>;
            key = try!(file.read_to_end().map_err(|_| V1KpdbError::ReadErr));
            return Ok(key);
        } else if file_size == 64 {
            // interpret characters as encoded hex if possible (e.g. "FF" => 0xff)
            match file.read_to_string() {
                Ok(e1) => {
                    match e1.as_slice().from_hex() {
                        Ok(e2) => return Ok(e2),
                        Err(_) => {},
                    }
                },
                Err(_) => {},
            }
            try!(file.seek(0i64, SeekStyle::SeekSet)
                 .map_err(|_| V1KpdbError::FileErr));
        }

        // Read up to 2048 bytes and hash them
        let mut hasher = Hasher::new(HashType::SHA256);

        loop {
            let mut read_bytes = 0;
            let mut buf: Vec<u8> = vec![];

            // We use this construct instead of file.read()
            // to handle EndOfFile _and_ get the number
            // of read bytes
            for _ in (0..2048) {
                match file.read_byte() {
                    Ok(o) => buf.push(o),
                    Err(e) => {
                        if e.kind == EndOfFile {
                            break;
                        } else {
                            return Err(V1KpdbError::ReadErr);
                        }
                    }
                }
                read_bytes += 1;
            }
            hasher.update(buf.as_slice());
            if read_bytes < 2048 {
                break;
            }
        }

        let key = hasher.finalize();
        Ok(key)
    }

    // Create the finalkey from the masterkey by encrypting it with some
    // random seeds from the database header and AES_ECB
    fn transform_key(mut masterkey: Vec<u8>, header: &V1Header) -> Vec<u8> {
        let crypter = symm::Crypter::new(symm::Type::AES_256_ECB);
        crypter.init(symm::Mode::Encrypt,
                     header.transf_randomseed.as_slice(), vec![]);
        for _ in (0..header.key_transf_rounds) {
            masterkey = crypter.update(masterkey.as_slice());
        }
        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(masterkey.as_slice());
        masterkey = hasher.finalize();

        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(header.final_randomseed.as_slice());
        hasher.update(masterkey.as_slice());

        // Zero out masterkey as it is not needed anymore
        unsafe { ptr::zero_memory(masterkey.as_ptr() as *mut c_void,
                                  masterkey.len());
                 mman::munlock(masterkey.as_ptr() as *const c_void,
                               masterkey.len() as size_t); }

        hasher.finalize()
    }

    // Decrypt the raw data and return it
    fn decrypt_it(finalkey: Vec<u8>,
                  crypted_database: Vec<u8>,
                  header: &V1Header) -> Vec<u8> {
        let mut db_tmp = symm::decrypt(symm::Type::AES_256_CBC,
                                       finalkey.as_slice(),
                                       header.iv.clone(), 
                                       crypted_database.as_slice());

        // Zero out finalkey as it is not needed anymore
        unsafe { ptr::zero_memory(finalkey.as_ptr() as *mut c_void,
                                  finalkey.len());
                 mman::munlock(finalkey.as_ptr() as *const c_void,
                               finalkey.len() as size_t); }

        // Delete padding from decrypted data
        let padding = db_tmp[db_tmp.len() - 1] as usize;
        let length = db_tmp.len();

        // resize() is safe as just padding is dropped
        db_tmp.resize(length-padding, 0);
        db_tmp
    }

    // Check some conditions
    fn check_decryption_success(header: &V1Header,
                                decrypted_content: &Vec<u8>) -> Result<(), V1KpdbError> {
        if (decrypted_content.len() > 2147483446) ||
            (decrypted_content.len() == 0 && header.num_groups > 0) {
            return Err(V1KpdbError::DecryptErr);
        }
        Ok(())
    }

    // Check some more conditions
    fn check_content_hash(header: &V1Header,
                          decrypted_content: &Vec<u8>) -> Result<(), V1KpdbError> {
        let mut hasher = Hasher::new(HashType::SHA256);
        hasher.update(decrypted_content.as_slice());
        if hasher.finalize() != header.contents_hash {
            return Err(V1KpdbError::HashErr);
        }
        Ok(())
    }

    // Parse the groups and put them into a vector
    fn parse_groups(header: &V1Header,
                    decrypted_database: &Vec<u8>,
                    remembered_pos: &mut usize) -> Result<(Vec<Rc<RefCell<V1Group>>>, Vec<u16>), V1KpdbError> {
        let mut pos: usize = 0;
        let mut group_number: u32 = 0;
        let mut levels: Vec<u16> = vec![];
        let mut cur_group = Rc::new(RefCell::new(V1Group::new()));
        let mut groups: Vec<Rc<RefCell<V1Group>>> = vec![];

        let mut field_type: u16;
        let mut field_size: u32;

        while group_number < header.num_groups {
            field_type = try!(slice_to_u16(&decrypted_database[pos..pos + 2]));
            pos += 2;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(&decrypted_database[pos..pos + 4]));
            pos += 4;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = V1Kpdb::read_group_field(cur_group.borrow_mut(),
                                             field_type, field_size, 
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

            pos += field_size as usize;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }
        
        *remembered_pos = pos;
        Ok((groups, levels))
    }

    // Parse the entries and put them into a vector
    fn parse_entries(header: &V1Header,
                     decrypted_database: &Vec<u8>,
                     remembered_pos: &usize) -> Result<Vec<Rc<RefCell<V1Entry>>>, V1KpdbError> {
        let mut pos = *remembered_pos;
        let mut entry_number: u32 = 0;
        let mut cur_entry = Rc::new(RefCell::new(V1Entry::new()));
        let mut entries: Vec<Rc<RefCell<V1Entry>>> = vec![];
        
        let mut field_type: u16;
        let mut field_size: u32;

        while entry_number < header.num_entries {
            field_type = try!(slice_to_u16(&decrypted_database[pos..pos + 2]));
            pos += 2;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(&decrypted_database[pos..pos + 4]));
            pos += 4;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = V1Kpdb::read_entry_field(cur_entry.borrow_mut(),
                                             field_type, field_size, 
                                             decrypted_database, pos);

            if field_type == 0xFFFF {
                entries.push(cur_entry);
                entry_number += 1;
                if entry_number == header.num_entries {
                    break;
                };
                cur_entry = Rc::new(RefCell::new(V1Entry::new()));
            }

            pos += field_size as usize;

            if pos > decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }

        Ok(entries)
    }

    // Read a group field from the raw data by it's field type
    fn read_group_field(mut group: RefMut<V1Group>, field_type: u16, field_size: u32,
                        decrypted_database: &Vec<u8>, pos: usize) -> Result<(), V1KpdbError> {
        let db_slice = if field_type == 0x0002 {
            &decrypted_database[pos..pos + (field_size - 1) as usize]
        } else {
            &decrypted_database[pos..pos + field_size as usize]
        };

        match field_type {
            0x0001 => group.id = try!(slice_to_u32(db_slice)),
            0x0002 => group.title = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
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

    // Read an entry field from the raw data by it's field type
    fn read_entry_field(mut entry: RefMut<V1Entry>, field_type: u16, field_size: u32,
                        decrypted_database: &Vec<u8>, pos: usize) -> Result<(), V1KpdbError> {
        let db_slice = match field_type {
            0x0004 ... 0x0008 | 0x000D =>
                &decrypted_database[pos..pos + (field_size - 1) as usize],
            _ => &decrypted_database[pos..pos + field_size as usize],
        };

        match field_type {
            0x0001 => entry.uuid = (0..field_size as usize)
                .map(|i| db_slice[i]).collect(),
            0x0002 => entry.group_id = try!(slice_to_u32(db_slice)),
            0x0003 => entry.image = try!(slice_to_u32(db_slice)),
            0x0004 => entry.title = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0005 => entry.url = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0006 => entry.username = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0007 => entry.password = SecureString::new(str::from_utf8(db_slice)
                                                         .unwrap().to_string()),
            0x0008 => entry.comment = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0009 => entry.creation = V1Kpdb::get_date(db_slice),
            0x000A => entry.last_mod = V1Kpdb::get_date(db_slice),
            0x000B => entry.last_access = V1Kpdb::get_date(db_slice),
            0x000C => entry.expire = V1Kpdb::get_date(db_slice),
            0x000D => entry.binary_desc = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x000E => entry.binary = (0..field_size as usize)
                .map(|i| db_slice[i]).collect(),
            _ => (),
        }

        Ok(())
    }

    // Parse a date. Taken from original KeePass-code
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

        Tm { year: year, month: month, day: day,
             hour: hour, minute: minute, second: second }
    }

    // Create the group tree from the level data
    fn create_group_tree(db: &mut V1Kpdb,
                         levels: Vec<u16>) -> Result<(), V1KpdbError> {
        if levels[0] != 0 {
            return Err(V1KpdbError::TreeErr);
        }
        
        for i in (0..db.groups.len()) {
            // level 0 means that the group is not a sub group. Hence add it as a children
            // of the root
            if levels[i] == 0 {
                db.groups[i].borrow_mut().parent = Some(db.root_group.clone());
                db.root_group.borrow_mut()
                    .children.push(db.groups[i].clone().downgrade());
                continue;
            }

            let mut j = i - 1;
            loop {
                // Find the first group with a lower level than the current.
                // That's the parent
                if levels[j] < levels[i] {
                    if levels[i] - levels[j] != 1 {
                        return Err(V1KpdbError::TreeErr);
                    }
                    db.groups[i].borrow_mut().parent = Some(db.groups[j].clone());
                    db.groups[j].borrow_mut()
                        .children.push(db.groups[i].clone().downgrade());
                    break;
                }
                // It's not possible that a group which comes after another
                // has a lower level. Hence all following groups which have not
                // level 0 are a subgroup of another.
                if j == 0 {
                    return Err(V1KpdbError::TreeErr);
                }
                j -= 1;
            }
        }

        // Sort entries to their groups
        // iter is secure as it is just obfuscated
        // pointer arithmetic to the entries vector
        for e in db.entries.as_slice().iter() {
            for g in db.groups.as_slice().iter() {
                if e.borrow().group_id == g.borrow().id {
                    g.borrow_mut().entries.push(e.clone().downgrade());
                    e.borrow_mut().group = Some(g.clone());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::V1Kpdb;
    use super::super::v1error::V1KpdbError;
    use super::super::v1header::V1Header;
    use super::super::super::sec_str::SecureString;

    #[test]
    fn test_new() {
        // No keyfile and password should give error as result
        let mut result = V1Kpdb::new("test/test_password.kdb".to_string(), None, None);
        match result {
            Ok(_)  => assert!(false),
            Err(e) => assert_eq!(e, V1KpdbError::PassErr),
        };

        // Test load at all and parameters
        result = V1Kpdb::new("test/test_both.kdb".to_string(), Some("test".to_string()),
                             Some("test/test_key".to_string()));
        assert!(result.is_ok());
        let mut db = result.ok().unwrap();
        assert_eq!(db.load().is_ok(), true);
        assert_eq!(db.path.as_slice(), "test/test_both.kdb");

        match db.password {
            Some(mut s) => {assert_eq!(s.string.as_slice(), "\0\0\0\0");
                        s.unlock();
                        assert_eq!(s.string.as_slice(), "test")},
            None => assert!(false),
        };
        match db.keyfile {
            Some(mut s) => {assert_eq!(s.string.as_slice(), "\0\0\0\0\0\0\0\0\0\0\0\0\0");
                            s.unlock();
                            assert_eq!(s.string.as_slice(), "test/test_key")},
            None => assert!(false),
        };
        
        // Test fail of load with wrong password
        result = V1Kpdb::new("test/test_password.kdb".to_string(), Some("tes".to_string()), None);
        assert!(result.is_ok());
        db = result.ok().unwrap();
        match db.load() {
            Ok(_)  => assert!(false),
            Err(e) => assert_eq!(e, V1KpdbError::HashErr),
        };
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
    fn test_keyfilekey() {
        let test_hash1 = vec![0x97, 0x57, 0xC1, 0xFB,
                              0x2F, 0xFB, 0x2B, 0xEA,
                              0x15, 0x82, 0x2B, 0x84,
                              0xF0, 0xBD, 0x50, 0xCF,
                              0xCC, 0x57, 0xE6, 0xF5,
                              0x56, 0xE0, 0x1D, 0x92,
                              0xF7, 0x38, 0xEF, 0x72,
                              0xB5, 0xC5, 0xA2, 0xEF];
        let test_hash2 = vec![0xB7, 0x4B, 0xCE, 0x14,
                              0x8B, 0xB9, 0xEF, 0xA2,
                              0xA3, 0xBE, 0xFC, 0xEC,
                              0xFD, 0xC5, 0x45, 0xFB,
                              0x4F, 0x5B, 0xF1, 0x38,
                              0x57, 0xF5, 0xC5, 0x6F,
                              0xB2, 0x6C, 0x11, 0x0F,
                              0x30, 0x3B, 0x48, 0x95];
        let test_hash3 = vec![0xA0, 0x6B, 0xB1, 0xE0,
                              0xDD, 0x95, 0x66, 0x92,
                              0x93, 0xF9, 0xF3, 0xBD,
                              0xC0, 0x6B, 0x40, 0x98,
                              0x48, 0x80, 0x08, 0xE0,
                              0x6E, 0x91, 0xA4, 0x6C,
                              0xEE, 0xBA, 0x2E, 0x25,
                              0xF7, 0xE7, 0x20, 0xA7];
        let test_hash4 = vec![0x35, 0x6F, 0xCD, 0x45,
                              0x2D, 0x70, 0xB8, 0xDA,
                              0x89, 0x8C, 0x9D, 0x16,
                              0x06, 0xAF, 0x62, 0x08,
                              0x71, 0xEB, 0xBD, 0x2D,
                              0x10, 0x45, 0x59, 0xB8,
                              0x75, 0x3B, 0x8A, 0xD5,
                              0x15, 0xAC, 0xBE, 0x4D];
        let test_hash5 = vec![0xB3, 0x61, 0x48, 0x08,
                              0xD3, 0xAE, 0xC9, 0x60,
                              0x97, 0x82, 0xED, 0x52,
                              0x59, 0x82, 0x89, 0x1D,
                              0x5F, 0xFA, 0x23, 0xC7,
                              0xCE, 0x8A, 0x00, 0x4F,
                              0x5D, 0x64, 0x27, 0xDD,
                              0x4F, 0x44, 0xAF, 0x8B];
        let test_hash6 = vec![0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF];

        let mut key1 = SecureString::new("test/32Bkey".to_string());
        let mut key2 = SecureString::new("test/64Bkey".to_string());
        let mut key3 = SecureString::new("test/128Bkey".to_string());
        let mut key4 = SecureString::new("test/2048Bkey".to_string());
        let mut key5 = SecureString::new("test/4096Bkey".to_string());
        let mut key6 = SecureString::new("test/64Bkey_alt".to_string());

        let mut result = V1Kpdb::get_keyfilekey(&mut key1);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash1);

        result = V1Kpdb::get_keyfilekey(&mut key2);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash2);

        result = V1Kpdb::get_keyfilekey(&mut key3);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash3);

        result = V1Kpdb::get_keyfilekey(&mut key4);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash4);

        result = V1Kpdb::get_keyfilekey(&mut key5);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash5);

        result = V1Kpdb::get_keyfilekey(&mut key6);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.ok().unwrap(), test_hash6);
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
        let sec_str = SecureString::new("test".to_string());
        let mut keyfile = None;
        
        let mut db_tmp: Vec<u8> = vec![];
        match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                       &mut Some(sec_str), &mut keyfile,
                                       &header) {
            Ok(e)  => {db_tmp = e},
            Err(_) => assert!(false),
        };
        let db_len = db_tmp.len();
        let db_clone = db_tmp.clone();
        // let test_clone = db_tmp.clone();

        let mut db_iter = db_tmp.into_iter();
        let db_iter2 = db_clone.into_iter();
        let mut db_iter3 = db_iter2.skip(db_len - 16);

        let test1: Vec<u8> = (0..16).map(|_| db_iter.next().unwrap()).collect();
        let test2: Vec<u8> = (0..16).map(|_| db_iter3.next().unwrap()).collect();

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
        let sec_str = SecureString::new("test".to_string());
        let mut keyfile = None;
        let mut decrypted_database: Vec<u8> = vec![];
        match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                       &mut Some(sec_str), &mut keyfile,
                                       &header) {
            Ok(e)  => { decrypted_database = e;},
            Err(_) => assert!(false),
        };
        
        let mut groups = vec![];
        match V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0us) {
            Ok((e, _)) => { groups = e; }, 
            Err(_) => assert!(false),
        }

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
        let sec_str = SecureString::new("test".to_string());
        let mut keyfile = None;
        let mut decrypted_database: Vec<u8> = vec![];
        match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                       &mut Some(sec_str), &mut keyfile,
                                       &header) {
            Ok(e)  => { decrypted_database = e;},
            Err(_) => assert!(false),
        };

        let mut entries = vec![];
        match V1Kpdb::parse_entries(&header, &decrypted_database, &mut 138us) {
            Ok(e)  => { entries = e; }, 
            Err(_) => assert!(false),
        }

        entries[0].borrow_mut().password.unlock();

        assert_eq!(entries[0].borrow().uuid, uuid);
        assert_eq!(entries[0].borrow().title.as_slice(), "foo");
        assert_eq!(entries[0].borrow().url.as_slice(), "foo");
        assert_eq!(entries[0].borrow().username.as_slice(), "foo");
        assert_eq!(entries[0].borrow().password.string.as_slice(), "DLE\"H<JZ|E");
        assert_eq!(entries[0].borrow().image, 1);
        assert_eq!(entries[0].borrow().group_id, 1);
        assert_eq!(entries[0].borrow().creation.year, 2014);
        assert_eq!(entries[0].borrow().creation.month, 2);
        assert_eq!(entries[0].borrow().creation.day, 26);
    }

    #[test]
    fn test_create_group_tree() {
        let mut db = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                                 Some("test".to_string()), None).ok().unwrap();
        
        let mut header = V1Header::new();
        let _ = header.read_header("test/test_parsing.kdb".to_string());
        let sec_str = SecureString::new("test".to_string());
        let mut keyfile = None;
        let mut decrypted_database: Vec<u8> = vec![];
        match V1Kpdb::decrypt_database("test/test_parsing.kdb".to_string(),
                                       &mut Some(sec_str), &mut keyfile,
                                       &header) {
            Ok(e)  => { decrypted_database = e;},
            Err(_) => assert!(false),
        };

        let mut pos = 0us;

        let mut groups = vec![];
        let mut levels = vec![];
        match V1Kpdb::parse_groups(&header, &decrypted_database, &mut pos) {
            Ok((e, l)) => { groups = e;
                            levels = l;}, 
            Err(_) => assert!(false),
        }
        db.groups = groups;

        let mut pos_cpy = pos;
        let mut entries = vec![];
        match V1Kpdb::parse_entries(&header, &decrypted_database, &mut pos_cpy) {
            Ok(e)  => { entries = e; }, 
            Err(_) => assert!(false),
        }
        db.entries = entries;

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

        assert_eq!(db.entries[0].borrow_mut().group.as_mut().unwrap().borrow().title.as_slice(), "Internet");
        assert_eq!(db.entries[1].borrow_mut().group.as_mut().unwrap().borrow().title.as_slice(), "11");
        assert_eq!(db.entries[2].borrow_mut().group.as_mut().unwrap().borrow().title.as_slice(), "12");
        assert_eq!(db.entries[3].borrow_mut().group.as_mut().unwrap().borrow().title.as_slice(), "21");
        assert_eq!(db.entries[4].borrow_mut().group.as_mut().unwrap().borrow().title.as_slice(), "22");
    }
}
