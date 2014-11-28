use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use openssl::crypto::symm;
use std::ptr;
use std::rand;

// Using String to get ownership of the input string
pub struct SecureString {
    pub string: String,
    encrypted_string: Vec<u8>,
    password: Vec<u8>,
    iv: Vec<u8>,
}

impl SecureString {
    pub fn new (string: String) -> SecureString {
        // Lock the string against swapping
        unsafe { mman::mlock(string.as_ptr() as *const c_void, string.len() as size_t); }
        let mut sec_str = SecureString { string: string, encrypted_string: vec![1u8],
                                         password: Vec::from_fn(32u, |x| rand::random::<u8>()),
                                         iv: Vec::from_fn(32u, |x| rand::random::<u8>()) };
        sec_str.lock();
        sec_str.delete();
        sec_str
    }

    pub fn delete(&self) {
        unsafe { ptr::zero_memory(self.string.as_ptr() as *mut c_void, self.string.len()) };
    }
    
    fn lock(&mut self) {
        self.encrypted_string = symm::encrypt(symm::Type::AES_256_CBC, self.password.as_slice(),
                                              self.iv.clone(), self.string.as_bytes());
    }

    pub fn unlock(&mut self) {
        self.string = String::from_utf8(symm::decrypt(symm::Type::AES_256_CBC, self.password.as_slice(),
                                                      self.iv.clone(), self.encrypted_string.as_slice())).unwrap();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.delete();
    }
}

#[cfg(test)]
mod tests {
    use super::SecureString;
    use std::str;

    #[test]
    fn test_new() {
        let str = "Hello, box!".to_string();
        // Ownership of str moves to SecureString <- secure input interface
        let mut sec_str = SecureString::new(str);
        sec_str.unlock();
        assert_eq!(sec_str.string.as_slice(), "Hello, box!");
    }

    #[test]
    fn test_delete() {
        let str = "delete".to_string();
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string.as_slice(), "\0\0\0\0\0\0");
        
        // Test with umlauts
        let str = "ä".to_string();
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string.as_slice(), "\0\0");        
    }

    #[test]
    fn test_lock() {
        let str = "delete".to_string();
        let mut sec_str = SecureString::new(str);

        assert!(str::from_utf8(sec_str.encrypted_string.as_slice()) !=  Some("delete"));

        sec_str.unlock();
        assert_eq!(sec_str.string.as_slice(), "delete");
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
