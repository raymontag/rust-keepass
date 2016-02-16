use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use openssl::crypto::symm;
use rand;
use std::ptr;

#[doc = "
SecureString implements a secure string. This means in particular:

* The input string moves to the struct, i.e. it's not just borrowed

* The string is encrypted with a random password for obfuscation

* mlock() is called on the string to prevent swapping

* A method to overwrite the string with zeroes is implemented

* The overwrite method is called on drop of the struct automatically

* Implements fmt::Show to prevent logging of the secrets, i.e. you can
  access the plaintext string only via the string value.
"]
pub struct SecureString {
    /// Holds the decrypted string if unlock() is called.
    /// Don't forget to call delete if you don't need the decrypted
    /// string anymore.
    /// Use String as type to move ownership to the struct.
    pub string: String,
    // Use of Vec instead of &[u8] because specific lifetimes aren't needed
    encrypted_string: Vec<u8>,
    password: Vec<u8>,
    iv: Vec<u8>,
}

impl SecureString {
    /// Create a new SecureString
    /// The input string should already lie on the heap, i.e. the type should
    /// be String and not &str, otherwise a copy of the plain text string would
    /// lie in memory. The string will be automatically encrypted and deleted.
    pub fn new(string: String) -> SecureString {
        // Lock the string against swapping
        unsafe {
            mman::mlock(string.as_ptr() as *const c_void, string.len() as size_t);
        }
        let mut sec_str = SecureString {
            string: string,
            encrypted_string: vec![],
            password: (0..32).map(|_| rand::random::<u8>()).collect(),
            iv: (0..32).map(|_| rand::random::<u8>()).collect(),
        };
        unsafe {
            mman::mlock(sec_str.encrypted_string.as_ptr() as *const c_void,
                        sec_str.encrypted_string.len() as size_t);
        }
        sec_str.lock();
        sec_str.delete();
        sec_str
    }

    /// Overwrite the string with zeroes. Call this everytime after unlock() if you don't
    /// need the string anymore.
    pub fn delete(&self) {
        // Use volatile_set_memory to make sure that the operation is executed.
        unsafe { ptr::write_bytes(self.string.as_ptr() as *mut c_void, 0u8, self.string.len()) };
    }

    fn lock(&mut self) {
        self.encrypted_string = symm::encrypt(symm::Type::AES_256_CBC,
                                              &self.password,
                                              self.iv.clone(),
                                              self.string.as_bytes());
    }

    /// Unlock the string, i.e. decrypt it and make it available via the string value.
    /// Don't forget to call delete() if you don't need the plain text anymore.
    pub fn unlock(&mut self) {
        self.string = String::from_utf8(symm::decrypt(symm::Type::AES_256_CBC,
                                                      &self.password,
                                                      self.iv.clone(),
                                                      &self.encrypted_string))
                          .unwrap();
    }
}

// string value and encrypted_string value will be overwritten with zeroes after drop of struct
impl Drop for SecureString {
    fn drop(&mut self) {
        self.delete();
        unsafe {
            mman::munlock(self.string.as_ptr() as *const c_void,
                          self.string.len() as size_t);
            ptr::write_bytes(self.encrypted_string.as_ptr() as *mut c_void,
                             0u8,
                             self.encrypted_string.len());
            mman::munlock(self.encrypted_string.as_ptr() as *const c_void,
                          self.encrypted_string.len() as size_t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SecureString;
    use std::str;
    use std::ptr::copy;

    #[test]
    fn test_drop() {
        let mut test_vec: Vec<u8> = Vec::with_capacity(4);
        let mut test_vec2: Vec<u8> = Vec::with_capacity(4);
        unsafe {
            test_vec.set_len(4);
            test_vec2.set_len(4);
            let str = "drop".to_string();
            let mut sec_str = SecureString::new(str);
            let enc_str_ptr = sec_str.encrypted_string.as_mut_ptr();
            let str_ptr = sec_str.string.as_mut_vec().as_mut_ptr();
            drop(sec_str);
            copy(enc_str_ptr, test_vec.as_mut_ptr(), 4);
            copy(str_ptr, test_vec2.as_mut_ptr(), 4);
        }
        assert_eq!(test_vec, vec![0u8, 0u8, 0u8, 0u8]);
        assert_eq!(test_vec2, vec![0u8, 0u8, 0u8, 0u8]);
    }
    #[test]
    fn test_new() {
        let str = "Hello, box!".to_string();
        // Ownership of str moves to SecureString <- secure input interface
        let mut sec_str = SecureString::new(str);
        sec_str.unlock();
        assert_eq!(sec_str.string, "Hello, box!");
    }

    #[test]
    fn test_delete() {
        let str = "delete".to_string();
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string, "\0\0\0\0\0\0");

        // Test with umlauts
        let str = "ä".to_string();
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string, "\0\0");
    }

    #[test]
    fn test_lock() {
        let str = "delete".to_string();
        let mut sec_str = SecureString::new(str);

        assert!(str::from_utf8(&sec_str.encrypted_string) != Ok("delete"));

        sec_str.unlock();
        assert_eq!(sec_str.string, "delete");
    }

    #[test]
    fn test_encryption() {
        let str = "delete".to_string();
        let sec_str = SecureString::new(str);

        let str = "delete".to_string();
        let mut sec_str2 = SecureString::new(str);
        assert!(sec_str.encrypted_string != sec_str2.encrypted_string);

        sec_str2.unlock();
        sec_str2.iv = sec_str.iv.clone();
        sec_str2.password = sec_str.password.clone();
        sec_str2.lock();
        assert_eq!(sec_str.encrypted_string, sec_str2.encrypted_string);
    }
}
