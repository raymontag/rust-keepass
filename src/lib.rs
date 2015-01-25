#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![allow(unstable)]

extern crate libc;
extern crate openssl;
extern crate "rustc-serialize" as rustc_serialize;

pub mod sec_str;
pub mod kpdb;
