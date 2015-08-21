#![crate_name="keepass"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
#![feature(rc_weak, vec_resize, vec_push_all, convert)]

extern crate libc;
extern crate openssl;
extern crate rustc_serialize;
extern crate chrono;
extern crate rand;

pub mod sec_str;
pub mod kpdb;
