#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![feature(old_io, old_path, core, alloc, collections, libc)]

extern crate libc;
extern crate openssl;
extern crate rand;
extern crate "rustc-serialize" as rustc_serialize;

pub mod sec_str;
pub mod kpdb;
