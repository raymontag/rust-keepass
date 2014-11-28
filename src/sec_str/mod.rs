// use std::ptr
//extern crate libc;
use libc::{c_void, size_t};
use libc::funcs::posix88::mman;

// Using String to get ownership of the input string
pub struct SecureString {
    pub string: String,
}

impl SecureString {
    pub fn new(string: String) -> SecureString {
        // Lock the string against swapping
        unsafe { mman::mlock(string.as_ptr() as *const c_void, string.len() as size_t); }
        SecureString { string: string }
    }
}

#[cfg(test)]
mod tests {
    use super::SecureString;

    #[test]
    fn test_new() {
        let str = "Hello, box!".to_string();
        // Ownership of str moves to SecureString <- secure input interface
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string, "Hello, box!".to_string());
    }
}
