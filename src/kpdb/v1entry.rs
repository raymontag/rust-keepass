use std::cell::RefCell;
use std::rc::Rc;

use super::tm::Tm;
use super::v1group::V1Group;
use super::super::sec_str::SecureString;

#[doc = "
Implements an entry in a KeePass v1.x database.
"]
pub struct V1Entry {
    /// UUID of the entry
    pub uuid: Vec<u8>,
    /// ID of the group holding the entry
    pub group_id: u32,
    /// Reference to the group holding the entry
    pub group: Option<Rc<RefCell<V1Group>>>,
    /// Used to specify an icon for the entry
    pub image: u32,
    /// Title of the entry
    pub title: String,
    /// URL for the login
    pub url: String,
    /// Username for the login
    pub username: String,
    /// Password for the login
    pub password: SecureString,
    /// Some comment about the entry
    pub comment: String,
    /// Descripton of the binary content
    pub binary_desc: String,
    /// ???
    pub binary: Vec<u8>,
    /// Date of creation
    pub creation: Tm,
    /// Date of last modification
    pub last_mod: Tm,
    /// Date of last access
    pub last_access: Tm,
    /// Expiration date
    pub expire: Tm,
}

impl V1Entry {
    /// Don't use this to create an empty entry.
    /// Normally you want to use the API
    /// of V1Kpdb to do this
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

