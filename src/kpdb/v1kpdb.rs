use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use std::cell::{RefCell, RefMut};
use std::old_io::SeekStyle;
use std::old_io::fs::File;
use std::old_io::IoErrorKind::EndOfFile;
use std::ptr;
use std::rc::Rc;
use std::str;

use openssl::crypto::hash::{Hasher, Type};
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
        let mut file = try!(File::open(&Path::new(path))
                            .map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(124i64, SeekStyle::SeekSet)
             .map_err(|_| V1KpdbError::FileErr));
        let crypted_database = try!(file.read_to_end()
                                    .map_err(|_| V1KpdbError::ReadErr));

        // Create the key and decrypt the database finally
        let masterkey = match (password, keyfile) {
            // Only password provided
            (&mut Some(ref mut p), &mut None) => try!(V1Kpdb::get_passwordkey(p)),
            // Only keyfile provided            
            (&mut None, &mut Some(ref mut k)) => try!(V1Kpdb::get_keyfilekey(k)),
            // Both provided
            (&mut Some(ref mut p), &mut Some(ref mut k)) => {
                // Get hashed keys...
                let passwordkey = try!(V1Kpdb::get_passwordkey(p));
                unsafe { mman::mlock(passwordkey.as_ptr() as *const c_void,
                                     passwordkey.len() as size_t); } 
                
                let keyfilekey = try!(V1Kpdb::get_keyfilekey(k));
                unsafe { mman::mlock(keyfilekey.as_ptr() as *const c_void,
                                     keyfilekey.len() as size_t); } 

                // ...and hash them together
                let mut hasher = Hasher::new(Type::SHA256);
                try!(hasher.write_all(passwordkey.as_slice())
                     .map_err(|_| V1KpdbError::DecryptErr));
                try!(hasher.write_all(keyfilekey.as_slice())
                     .map_err(|_| V1KpdbError::DecryptErr));

                // Zero out unneeded keys
                unsafe { ptr::zero_memory(passwordkey.as_ptr() as *mut c_void,
                                          passwordkey.len());
                         ptr::zero_memory(keyfilekey.as_ptr() as *mut c_void,
                                          keyfilekey.len());
                         mman::munlock(passwordkey.as_ptr() as *const c_void,
                                       passwordkey.len() as size_t);
                         mman::munlock(keyfilekey.as_ptr() as *const c_void,
                                       keyfilekey.len() as size_t); }
                
                hasher.finish()
            },
            (&mut None, &mut None) => return Err(V1KpdbError::PassErr),
        };
        unsafe { mman::mlock(masterkey.as_ptr() as *const c_void,
                             masterkey.len() as size_t); }
        
        let finalkey = try!(V1Kpdb::transform_key(masterkey, header));
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
    fn get_passwordkey(password: &mut SecureString) -> Result<Vec<u8>, V1KpdbError> {
        // unlock SecureString
        password.unlock();
        // password.string.as_bytes() is secure as just a reference is returned
        let password_string = password.string.as_bytes();

        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(password_string)
             .map_err(|_| V1KpdbError::DecryptErr));
        // Zero out plaintext password
        password.delete();

        Ok(hasher.finish())
    }

    // Get key from keyfile
    fn get_keyfilekey(keyfile: &mut SecureString) -> Result<Vec<u8>, V1KpdbError> {
        //unlock SecureString
        keyfile.unlock();
        // keyfile.string.as_bytes() is secure as just a reference is returned
        let keyfile_path = keyfile.string.as_bytes();
        
        let mut file = try!(File::open(&Path::new(keyfile_path))
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
        let mut hasher = Hasher::new(Type::SHA256);

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
            try!(hasher.write_all(buf.as_slice())
                 .map_err(|_| V1KpdbError::DecryptErr));
            if read_bytes < 2048 {
                break;
            }
        }

        let key = hasher.finish();
        Ok(key)
    }

    // Create the finalkey from the masterkey by encrypting it with some
    // random seeds from the database header and AES_ECB
    fn transform_key(mut masterkey: Vec<u8>, header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let crypter = symm::Crypter::new(symm::Type::AES_256_ECB);
        crypter.init(symm::Mode::Encrypt,
                     header.transf_randomseed.as_slice(), vec![]);
        for _ in (0..header.key_transf_rounds) {
            masterkey = crypter.update(masterkey.as_slice());
        }
        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(masterkey.as_slice())
             .map_err(|_| V1KpdbError::DecryptErr));
        masterkey = hasher.finish();

        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(header.final_randomseed.as_slice())
             .map_err(|_| V1KpdbError::DecryptErr));
        try!(hasher.write_all(masterkey.as_slice())
             .map_err(|_| V1KpdbError::DecryptErr));

        // Zero out masterkey as it is not needed anymore
        unsafe { ptr::zero_memory(masterkey.as_ptr() as *mut c_void,
                                  masterkey.len());
                 mman::munlock(masterkey.as_ptr() as *const c_void,
                               masterkey.len() as size_t); }

        Ok(hasher.finish())
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
        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(decrypted_content.as_slice())
             .map_err(|_| V1KpdbError::DecryptErr));
        if hasher.finish() != header.contents_hash {
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

