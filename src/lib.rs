#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![feature(vec_resize, convert, core_intrinsics)]

extern crate libc;
extern crate openssl;
extern crate rustc_serialize;
extern crate chrono;
extern crate rand;
extern crate uuid;

pub mod sec_str;
pub mod kpdb;
