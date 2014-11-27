// use std::ptr
//extern crate libc;
use libc::{c_void, size_t};
use libc::funcs::posix88::mman;

pub struct SecureString {
    pub string: Box<String>,
}

impl SecureString {
    pub fn new(string: Box<String>) -> SecureString {
        unsafe { mman::mlock(string.as_ptr() as *const c_void, string.len() as size_t); }
        SecureString { string: string }
    }
}

#[cfg(test)]
mod tests {
    use super::SecureString;

    #[test]
    fn test_new() {
        let str = box "Hello, box!".to_string();
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string, box "Hello, box!".to_string())
    }
}
