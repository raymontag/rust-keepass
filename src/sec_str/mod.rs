use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use std::ptr;

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

    pub fn new_from_str(string: &str) -> SecureString {
	let s: String = string.to_string();
    	SecureString::new(s)
    }

    pub fn delete(&self) {
        unsafe { ptr::zero_memory(self.string.as_ptr() as *mut c_void, self.string.len()) };
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

    #[test]
    fn test_new() {
        let str = "Hello, box!".to_string();
        // Ownership of str moves to SecureString <- secure input interface
        let sec_str = SecureString::new(str);
        assert_eq!(sec_str.string.as_slice(), "Hello, box!");
    }

    #[test]
    fn test_new_from_str() {
        let str = "Hello, box!";
        // Ownership of str moves to SecureString <- secure input interface
        let sec_str = SecureString::new_from_str(str);
        assert_eq!(sec_str.string.as_slice(), "Hello, box!");
    }

    #[test]
    fn test_delete() {
        let str = "delete".to_string();
        let sec_str = SecureString::new(str);
        sec_str.delete();
        assert_eq!(sec_str.string.as_slice(), "\0\0\0\0\0\0");
        
        // Test with umlauts
        let str = "ä".to_string();
        let sec_str = SecureString::new(str);
        sec_str.delete();
        assert_eq!(sec_str.string.as_slice(), "\0\0");        

	// Test with new_from_str
	let str = "deletä";
	let sec_str = SecureString::new_from_str(str);
	sec_str.delete();
	assert_eq!(sec_str.string.as_slice(), "\0\0\0\0\0\0\0");
    }
}
