use std::cell::RefCell;
use std::rc::Rc;

use super::tm::Tm;
use super::v1group::V1Group;
use super::super::sec_str::SecureString;

pub struct V1Entry {
    pub uuid: Vec<u8>,
    pub group_id: u32,
    pub group: Option<Rc<RefCell<V1Group>>>,
    pub image: u32,
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: SecureString,
    pub comment: String,
    pub binary_desc: String,
    pub binary: Vec<u8>,
    pub creation: Tm,
    pub last_mod: Tm,
    pub last_access: Tm,
    pub expire: Tm,
}

impl V1Entry {
    pub fn new() -> V1Entry {
        V1Entry { uuid: vec![],
                  group_id: 0,
                  group: None,
                  image: 0,
                  title: "".to_string(),
                  url: "".to_string(),
                  username: "".to_string(),
                  password: SecureString::new("".to_string()),
                  comment: "".to_string(),
                  binary_desc: "".to_string(),
                  binary: vec![],
                  creation: Tm::new(),
                  last_mod: Tm::new(),
                  last_access: Tm::new(),
                  expire: Tm::new(),
        }
    }
}

