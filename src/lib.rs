#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![feature(convert, libc, alloc, collections)]

extern crate libc;
extern crate openssl;
extern crate rand;
extern crate rustc_serialize;
extern crate chrono;

pub mod sec_str;
pub mod kpdb;
