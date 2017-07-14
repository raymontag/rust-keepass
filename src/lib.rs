#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

extern crate libc;
extern crate openssl;
extern crate rustc_serialize;
extern crate chrono;
extern crate rand;
extern crate uuid;

pub mod sec_str;
pub mod kpdb;
pub mod common;

