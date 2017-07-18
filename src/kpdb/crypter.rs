use libc::{c_void, mlock, munlock, size_t};
use std::fs::File;
use std::io::{Seek, SeekFrom, Read, Write};

use openssl::hash;
use openssl::symm;
use rustc_serialize::hex::FromHex;

use sec_str::SecureString;
use common::common::write_array_volatile;
use kpdb::v1error::V1KpdbError;
use kpdb::v1header::V1Header;

// implements a crypter to de- and encrypt a KeePass DB
pub struct Crypter {
    password: Option<SecureString>,
    keyfile: Option<SecureString>,
}

// Sensitive data in Crypter overall
// * finalkey: created in transform_key, zeroed out in en-/decrypt_raw
// * masterkey: created in get_finalkey, lock depends on method, zeroed out in transform_key
// * decrypted_database:
// ** decryption: created in decrypt_raw, moved out of Crypted
// ** encryption: created and locked outside of Crypter, zeroed out in encrypt_raw
// * passwordkey: created in get_passwordkey, zeroed out in get_finalkey
// * keyfilekey: created in get_keyfilekey, zeroed out in get_finalkey
// * masterkey_tmp: created in get_finalkey, moved into masterkey
// * password: is a reference to a SecureString and is handled correctly in get_passwordkey 
// * password_string: is a reference to password.string
// * keyfile: is a reference to a SecureString and is handled correctly in get_keyfilekey 
// * key: created in get_keyfilekey, moved into keyfilekey or is zeroed out in get_keyfile_key
// * decoded_key: created in get_keyfilekey, moved into keyfilekey
// * buf: created and zeroed out in get_keyfilekey
impl Crypter {
    // Decrypt the database and return the raw data as Vec<u8>
    // Sensitive data in this function:
    //
    // * password
    // * keyfile
    //
    // Both are moved out of new into SecureString
    pub fn new(password: Option<String>,
               keyfile: Option<String>)
               -> Result<Crypter, V1KpdbError> {
        match (password, keyfile) {
            (Some(p), None) => Ok(Crypter { password: Some(SecureString::new(p)),
                                            keyfile: None, }),
            (None, Some(k)) => Ok(Crypter { password: None,
                                         keyfile: Some(SecureString::new(k)), }),
            (Some(p), Some(k)) => Ok(Crypter { password: Some(SecureString::new(p)),
                                               keyfile: Some(SecureString::new(k)), }),
            (None, None) => Err(V1KpdbError::PassErr),
        }
        
    }

    // Sensitive data in this function:
    //
    // * password moved out of function
    //
    // Old password's SecureString is deleted through Drop
    pub fn change_password(&mut self, password: Option<String>) -> Result<(), V1KpdbError> {
        // Weird construct because self.keyfile in second match
        // creates compiler errors due to invalid borrowing
        let keyfile_option = match self.keyfile {
            Some(_) => Some(()),
            None => None,
        };
        match (password, keyfile_option) {
            (None, None) => return Err(V1KpdbError::PassErr),
            (None, Some(())) => self.password = None,
            (Some(p), _) => self.password = Some(SecureString::new(p)),
        };

        Ok(())
    }

    // Sensitive data in this function:
    //
    // * keyfile moved out of function
    //
    // Old keyfiles's SecureString is deleted through Drop
    pub fn change_keyfile(&mut self, keyfile: Option<String>) -> Result<(), V1KpdbError> {
        // Weird construct because self.password in second match
        // creates compiler errors due to invalid borrowing
        let password_option = match self.password {
            Some(_) => Some(()),
            None => None,
        };

        match (password_option, keyfile) {
            (None, None) => return Err(V1KpdbError::PassErr),
            (Some(()), None) => self.keyfile = None,
            (_, Some(k)) => self.keyfile = Some(SecureString::new(k)),
        };

        Ok(())
    }
    
    // Sensitive data in this function:
    // * finalkey (locked: transform_key)
    // * decrypted_database (locked: decrypt_raw)
    //
    // At the end of this function:
    // * decrypted database moved out of function
    // * finalkey has moved to decrypt_raw
    //
    // decrypted database is locked through decrypt_raw
    pub fn decrypt_database(&mut self, header: &V1Header, encrypted_database: Vec<u8>) -> Result<Vec<u8>, V1KpdbError> {
        let finalkey = try!(self.get_finalkey(header));
        let decrypted_database = try!(Crypter::decrypt_raw(header, encrypted_database, finalkey));
        try!(Crypter::check_decryption_success(header, &decrypted_database));
        try!(Crypter::check_content_hash(header, &decrypted_database));

        Ok(decrypted_database)
    }

    // Sensitive data in this function:
    // * finalkey (locked: transform_key)
    // * decrypted_database
    //
    // At the end of this function:
    // * decrypted database has moved to encrypt_raw
    // * finalkey has moved to encrypt_raw
    pub fn encrypt_database(&mut self, header: &V1Header, decrypted_database: Vec<u8>) -> Result<Vec<u8>, V1KpdbError> {
        let finalkey = try!(self.get_finalkey(header));
        Crypter::encrypt_raw(header, decrypted_database, finalkey)
    }

    // Sensitive data in this function:
    // * masterkey
    // * passwordkey (locked: get_passwordkey)
    // * keyfilekey (locked: get_keyfilekey)
    // * finalkey (locked: transform_key)
    // * masterkey_tmp
    //
    // At the end of this function:
    // * masterkey has moved to transform_key and is locked
    // * passwordkey is zeroed out
    // * keyfilekey is zeroed out
    // * finalkey moved out of function
    // * masterkey_tmp is locked and moved into masterkey
    //
    // passwordkey and keyfilekey are locked until procession
    // p and k are locked through SecureString
    fn get_finalkey(&mut self, header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let masterkey = match (&mut self.password, &mut self.keyfile) {
            // Only password provided
            (&mut Some(ref mut p), &mut None) => try!(Crypter::get_passwordkey(p)),
            // Only keyfile provided
            (&mut None, &mut Some(ref mut k)) => try!(Crypter::get_keyfilekey(k)),
            // Both provided
            (&mut Some(ref mut p), &mut Some(ref mut k)) => {
                // Get hashed keys...
                let passwordkey = try!(Crypter::get_passwordkey(p));

                let keyfilekey = try!(Crypter::get_keyfilekey(k));

                // ...and hash them together
                let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Can't hash passwords!?");
                try!(hasher.write_all(&passwordkey)
                     .map_err(|_| V1KpdbError::DecryptErr));
                try!(hasher.write_all(&keyfilekey)
                     .map_err(|_| V1KpdbError::DecryptErr));

                let masterkey_tmp = hasher.finish2().expect("Can't hash masterkey");
                // Zero out unneeded keys and lock masterkey
                unsafe {
                    write_array_volatile(passwordkey.as_ptr() as *mut u8,
                                         0u8,
                                         passwordkey.len());
                    write_array_volatile(keyfilekey.as_ptr() as *mut u8,
                                         0u8,
                                         keyfilekey.len());
                    munlock(passwordkey.as_ptr() as *const c_void,
                                  passwordkey.len() as size_t);
                    munlock(keyfilekey.as_ptr() as *const c_void,
                                  keyfilekey.len() as size_t);
                    mlock(masterkey_tmp.as_ptr() as *const c_void,
                                masterkey_tmp.len() as size_t);
                }
                masterkey_tmp.to_vec()
            }
            (&mut None, &mut None) => return Err(V1KpdbError::PassErr),
        };
        let finalkey = try!(Crypter::transform_key(masterkey, header));

        Ok(finalkey)
    }
    
    // Hash the password string to create a decryption key from that
    // Sensitive data in this function:
    // * password
    // * password_string
    // * passwordkey
    //
    // At the end of this function:
    // * password is zeroed out
    // * password_string is deleted (is a reference to password.string)
    // * passwordkey is moved out of function and locked
    fn get_passwordkey(password: &mut SecureString) -> Result<Vec<u8>, V1KpdbError> {
        password.unlock();
        let password_string = password.string.as_bytes();

        let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Can't creater hasher!?");
        try!(hasher.write_all(password_string)
             .map_err(|_| V1KpdbError::DecryptErr));
        password.delete();

        // hasher.finish() is a move and therefore secure
        let passwordkey = hasher.finish2().expect("Can't hash password!?");
        unsafe {
            mlock(passwordkey.as_ptr() as *const c_void,
                        passwordkey.len() as size_t);
        }
        Ok(passwordkey.to_vec())
    }

    // Get key from keyfile
    // Sensitive data in this function:
    // * keyfile
    // * key
    // * decoded_key
    // * buf
    // * file
    //
    // At the end of this function:
    // * keyfile is deleted
    // * key has moved out of function and is locked or is deleted (file_size==64)
    // * decoded_key has moved out of function and is locked
    // * buf is deleted
    // * file ... TODO
    //
    // buf and key are locked during procession
    fn get_keyfilekey(keyfile: &mut SecureString) -> Result<Vec<u8>, V1KpdbError> {
        keyfile.unlock();

        let mut file = try!(File::open(&keyfile.string).map_err(|_| V1KpdbError::FileErr));
        // unsafe {
        //     mlock(file.as_ptr() as *const c_void,
        //                 file.len() as size_t);
        // }

        keyfile.delete();

        let file_size = try!(file.seek(SeekFrom::End(0i64))
                                 .map_err(|_| V1KpdbError::FileErr));
        try!(file.seek(SeekFrom::Start(0u64))
                 .map_err(|_| V1KpdbError::FileErr));

        if file_size == 32 {
            let mut key: Vec<u8> = vec![];
            try!(file.read_to_end(&mut key).map_err(|_| V1KpdbError::ReadErr));
            unsafe {
                mlock(key.as_ptr() as *const c_void,
                            key.len() as size_t);
                // intrinsics::volatile_set_memory(&file as *mut c_void,
                //                                 0u8,
                //                                 mem::size_of::<File>());

            }
            return Ok(key);
        } else if file_size == 64 {
            // interpret characters as encoded hex if possible (e.g. "FF" => 0xff)
            let mut key: String = "".to_string();
            unsafe {
                mlock(key.as_ptr() as *const c_void,
                            key.len() as size_t);
            }
            match file.read_to_string(&mut key) {
                Ok(_) => {
                    match (&key[..]).from_hex() {
                        Ok(decoded_key) => {
                            unsafe {
                                // intrinsics::volatile_set_memory(&file as *mut c_void,
                                //                                 0u8,
                                //                                 mem::size_of::<File>());
                                mlock(decoded_key.as_ptr() as *const c_void,
                                            decoded_key.len() as size_t);
                                write_array_volatile(key.as_ptr() as *mut u8,
                                                     0u8,
                                                     key.len());
                                munlock(key.as_ptr() as *const c_void,
                                              key.len() as size_t);

                            }
                            return Ok(decoded_key)
                        },
                        Err(_) => {}
                    }
                }
                Err(_) => {
                    unsafe {
                        write_array_volatile(key.as_ptr() as *mut u8,
                                             0u8,
                                             key.len());
                        munlock(key.as_ptr() as *const c_void,
                                      key.len() as size_t);
                        
                    }
                    try!(file.seek(SeekFrom::Start(0u64))
                         .map_err(|_| V1KpdbError::FileErr));
                }
            }
        }

        // Read up to 2048 bytes and hash them
        let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Can't create hasher!?");
        let mut buf: Vec<u8> = vec![];
        unsafe {
            mlock(buf.as_ptr() as *const c_void,
                        buf.len() as size_t);
        }

        loop {
            buf = vec![0; 2048];
            match file.read(&mut buf[..]) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    };
                    buf.truncate(n);
                    try!(hasher.write_all(&buf[..])
                         .map_err(|_| V1KpdbError::DecryptErr));
                    unsafe {
                        write_array_volatile(buf.as_ptr() as *mut u8, 0u8, buf.len())
                    };

                }
                Err(_) => {
                    return Err(V1KpdbError::ReadErr);
                }
            }
        }

        let key = hasher.finish2().expect("Can't hash key!?");
        unsafe {
            // intrinsics::volatile_set_memory(&file as *mut c_void,
            //                                 0u8,
            //                                 mem::size_of::<File>());
            munlock(buf.as_ptr() as *const c_void,
                          buf.len() as size_t);
            mlock(key.as_ptr() as *const c_void,
                        key.len() as size_t);
            
        }

        Ok(key.to_vec())
    }

    // Create the finalkey from the masterkey by encrypting it with some
    // random seeds from the database header and AES_ECB
    // 
    // Sensitive data in this function:
    // * masterkey (locked: get_finalkey)
    // * finalkey
    //
    // At the end of this function:
    // * masterkey is zeroed out
    // * finalkey is locked and moved out of function
    fn transform_key(mut masterkey: Vec<u8>, header: &V1Header) -> Result<Vec<u8>, V1KpdbError> {
        let mut crypter = symm::Crypter::new(symm::Cipher::aes_256_ecb(),
                                             symm::Mode::Encrypt,
                                             &header.transf_randomseed,
                                             None).expect("Can't create crypter!?");
        let mut transformed_key = vec![0; masterkey.len() + symm::Cipher::aes_256_cbc().block_size()];
        for _ in 0..header.key_transf_rounds {
            let _ = crypter.update(&masterkey, &mut transformed_key);
            transformed_key.truncate(masterkey.len());
            masterkey = transformed_key.clone();
            transformed_key = vec![0; masterkey.len() + symm::Cipher::aes_256_cbc().block_size()];
        }
        
        // Because rust-openssl needs a vector length of masterkey.len() + block_size
        
        let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Could not create Hasher!?");
        try!(hasher.write_all(&masterkey)
             .map_err(|_| V1KpdbError::DecryptErr));
        masterkey = hasher.finish2().expect("Could not hash masterkey!?").to_vec();
        let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Could not create Hasher!?");
        try!(hasher.write_all(&header.final_randomseed)
             .map_err(|_| V1KpdbError::DecryptErr));
        try!(hasher.write_all(&masterkey)
             .map_err(|_| V1KpdbError::DecryptErr));
        let finalkey = hasher.finish2().expect("Could not hash finalkey!?");

        // Zero out masterkey as it is not needed anymore
        unsafe {
            write_array_volatile(masterkey.as_ptr() as *mut u8,
                                 0u8,
                                 masterkey.len());
            munlock(masterkey.as_ptr() as *const c_void,
                          masterkey.len() as size_t);
            mlock(finalkey.as_ptr() as *const c_void, finalkey.len() as size_t);

        }

        Ok(finalkey.to_vec())
    }

    // Decrypt the raw data and return it
    //
    // Sensitive data in this function:
    // * finalkey (locked: transform_key)
    // * decrypted_database
    //
    // At the end of this function:
    // * finalkey is deleted
    // * decrypted_database is locked and moved out of function
    //
    // finalkey is locked through transform_key
    fn decrypt_raw(header: &V1Header, encrypted_database: Vec<u8>, finalkey: Vec<u8>) -> Result<Vec<u8>, V1KpdbError> {
        let mut decrypted_database = try!(symm::decrypt(symm::Cipher::aes_256_cbc(),
                                                        &finalkey,
                                                        Some(header.iv.as_slice()),
                                                        &encrypted_database).map_err(|_| V1KpdbError::DecryptErr));

        // Zero out finalkey as it is not needed anymore
        unsafe {
            write_array_volatile(finalkey.as_ptr() as *mut u8, 0u8, finalkey.len());
            munlock(finalkey.as_ptr() as *const c_void, finalkey.len() as size_t);
        }

        // Delete padding from decrypted data
        let padding = decrypted_database[decrypted_database.len() - 1] as usize;
        let length = decrypted_database.len();

        // resize() is safe as just padding is dropped
        decrypted_database.resize(length - padding, 0);
        unsafe {
            mlock(decrypted_database.as_ptr() as *const c_void, decrypted_database.len() as size_t);
        }

        Ok(decrypted_database)
    }

    fn encrypt_raw(header: &V1Header, decrypted_database: Vec<u8>, finalkey: Vec<u8>) -> Result<Vec<u8>, V1KpdbError> {
        let encrypted_database = try!(symm::encrypt(symm::Cipher::aes_256_cbc(),
                                                    &finalkey,
                                                    Some(header.iv.as_slice()),
                                                    &decrypted_database).map_err(|_| V1KpdbError::EncryptErr));
        
        // Zero out finalkey as it is not needed anymore
        unsafe {
            write_array_volatile(finalkey.as_ptr() as *mut u8, 0u8, finalkey.len());
            munlock(finalkey.as_ptr() as *const c_void, finalkey.len() as size_t);
            write_array_volatile(decrypted_database.as_ptr() as *mut u8, 0u8, decrypted_database.len());
            munlock(decrypted_database.as_ptr() as *const c_void, decrypted_database.len() as size_t);
        }

        Ok(encrypted_database)
    }

    // Check some conditions
    // Sensitive data in this function
    // * decrypted_content (locked: decrypt_raw)
    //
    // At the end of the function:
    // * decrypted_content hasn't changed (it's a reference)
    fn check_decryption_success(header: &V1Header,
                                decrypted_content: &Vec<u8>)
                                -> Result<(), V1KpdbError> {
        if (decrypted_content.len() > 2147483446) ||
           (decrypted_content.len() == 0 && header.num_groups > 0) {
               return Err(V1KpdbError::DecryptErr);
           }
        Ok(())
    }

    // Sensitive data in this function
    // * decrypted_content (locked: decrypt_raw or ...)
    //
    // At the end of the function:
    // * decrypted_content hasn't changed (it's a reference)
    pub fn get_content_hash(decrypted_content: &Vec<u8>) -> Result<Vec<u8>, V1KpdbError> {
        let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256()).expect("Could not create hasher!?");
        try!(hasher.write_all(&decrypted_content)
             .map_err(|_| V1KpdbError::DecryptErr));
        Ok(hasher.finish2().expect("Can't hash decrypted concent!?").to_vec())
    }
    
    // Check some more conditions
    // Sensitive data in this function
    // * decrypted_content (locked: decrypt_raw)
    //
    // At the end of the function:
    // * decrypted_content hasn't changed (it's a reference)
    fn check_content_hash(header: &V1Header,
                          decrypted_content: &Vec<u8>)
                          -> Result<(), V1KpdbError> {
        let content_hash = try!(Crypter::get_content_hash(decrypted_content));
        if content_hash != header.content_hash {
            return Err(V1KpdbError::HashErr);
        }
        Ok(())
    }
}
