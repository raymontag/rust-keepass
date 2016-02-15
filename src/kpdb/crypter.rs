use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use std::io::{Seek, SeekFrom, Read, Write};
use std::fs::File;
use std::intrinsics;

use openssl::crypto::hash::{Hasher, Type};
use openssl::crypto::symm;
use rustc_serialize::hex::FromHex;

use super::v1header::V1Header;
use super::v1error::V1KpdbError;
use super::super::sec_str::SecureString;

// implements a crypter to de- and encrypt a KeePass DB
pub struct Crypter {
    path: String,
    password: Option<SecureString>,
    keyfile: Option<SecureString>,
}

impl Crypter {
    // Decrypt the database and return the raw data as Vec<u8>
    pub fn new(path: String, password: Option<SecureString>,
               keyfile: Option<SecureString>) -> Crypter {
        Crypter { path: path, password: password, keyfile: keyfile }
    }
    
    pub fn decrypt_database(&mut self, header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let mut file = try!(File::open(self.path.clone())
                            .map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(SeekFrom::Start(124u64))
             .map_err(|_| V1KpdbError::FileErr));
        let mut crypted_database: Vec<u8> = vec![];
        try!(file.read_to_end(&mut crypted_database)
             .map_err(|_| V1KpdbError::ReadErr));

        // Create the key and decrypt the database finally
        let masterkey = match (&mut self.password, &mut self.keyfile) {
            // Only password provided
            (&mut Some(ref mut p), &mut None) => try!(Crypter::get_passwordkey(p)),
            // Only keyfile provided            
            (&mut None, &mut Some(ref mut k)) => try!(Crypter::get_keyfilekey(k)),
            // Both provided
            (&mut Some(ref mut p), &mut Some(ref mut k)) => {
                // Get hashed keys...
                let passwordkey = try!(Crypter::get_passwordkey(p));
                unsafe { mman::mlock(passwordkey.as_ptr() as *const c_void,
                                     passwordkey.len() as size_t); } 
                
                let keyfilekey = try!(Crypter::get_keyfilekey(k));
                unsafe { mman::mlock(keyfilekey.as_ptr() as *const c_void,
                                     keyfilekey.len() as size_t); } 

                // ...and hash them together
                let mut hasher = Hasher::new(Type::SHA256);
                try!(hasher.write_all(&passwordkey)
                     .map_err(|_| V1KpdbError::DecryptErr));
                try!(hasher.write_all(&keyfilekey)
                     .map_err(|_| V1KpdbError::DecryptErr));

                // Zero out unneeded keys
                unsafe { intrinsics::volatile_set_memory(passwordkey.as_ptr() as *mut c_void, 0u8,
                                                         passwordkey.len());
                         intrinsics::volatile_set_memory(keyfilekey.as_ptr() as *mut c_void, 0u8,
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
        let finalkey = try!(Crypter::transform_key(masterkey, header));
        unsafe { mman::mlock(finalkey.as_ptr() as *const c_void,
                             finalkey.len() as size_t); }
        
        let decrypted_database = Crypter::decrypt_it(finalkey, crypted_database, header);
        try!(Crypter::check_decryption_success(header, &decrypted_database));
        try!(Crypter::check_content_hash(header, &decrypted_database));
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

        let mut file = try!(File::open(&keyfile.string)
                            .map_err(|_| V1KpdbError::FileErr));
        // Zero out plaintext keyfile path
        keyfile.delete();

        let file_size = try!(file.seek(SeekFrom::End(0i64))
                             .map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(SeekFrom::Start(0u64))
             .map_err(|_| V1KpdbError::FileErr));
        
        if file_size == 32 {
            let mut key: Vec<u8> = vec![];
            try!(file.read_to_end(&mut key).map_err(|_| V1KpdbError::ReadErr));
            return Ok(key);
        } else if file_size == 64 {
            // interpret characters as encoded hex if possible (e.g. "FF" => 0xff)
            let mut key: String = "".to_string();
            match file.read_to_string(&mut key) {
                Ok(_) => {
                    match key.as_str().from_hex() {
                        Ok(e2) => return Ok(e2),
                        Err(_) => {},
                    }
                },
                Err(_) => {},
            }
            try!(file.seek(SeekFrom::Start(0u64))
                 .map_err(|_| V1KpdbError::FileErr));
        }

        // Read up to 2048 bytes and hash them
        let mut hasher = Hasher::new(Type::SHA256);
        let mut buf: Vec<u8>;
        
        loop {
            buf = vec![0; 2048];
            match file.read(&mut buf[..]) {
                Ok(n) =>
                {
                    if n == 0 {break};
                    buf.truncate(n);
                    try!(hasher.write_all(buf.as_slice())
                         .map_err(|_| V1KpdbError::DecryptErr));
                    unsafe { intrinsics::volatile_set_memory(buf.as_ptr() as *mut c_void,
                                                             0u8, buf.len()) };

                },
                Err(_) => {
                    return Err(V1KpdbError::ReadErr);
                }
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
                     &header.transf_randomseed, vec![]);
        for _ in 0..header.key_transf_rounds {
            masterkey = crypter.update(&masterkey);
        }
        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(&masterkey)
             .map_err(|_| V1KpdbError::DecryptErr));
        masterkey = hasher.finish();

        let mut hasher = Hasher::new(Type::SHA256);
        try!(hasher.write_all(&header.final_randomseed)
             .map_err(|_| V1KpdbError::DecryptErr));
        try!(hasher.write_all(&masterkey)
             .map_err(|_| V1KpdbError::DecryptErr));

        // Zero out masterkey as it is not needed anymore
        unsafe { intrinsics::volatile_set_memory(masterkey.as_ptr() as *mut c_void, 0u8,
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
                                       &finalkey,
                                       header.iv.clone(), 
                                       &crypted_database);

        // Zero out finalkey as it is not needed anymore
        unsafe { intrinsics::volatile_set_memory(finalkey.as_ptr() as *mut c_void, 0u8,
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
        try!(hasher.write_all(&decrypted_content)
             .map_err(|_| V1KpdbError::DecryptErr));
        if hasher.finish() != header.contents_hash {
            return Err(V1KpdbError::HashErr);
        }
        Ok(())
    }
}
