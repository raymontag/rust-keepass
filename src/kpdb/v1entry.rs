use std::cell::RefCell;
use std::rc::Rc;

use chrono::{DateTime, Local, TimeZone};
use uuid::Uuid;

use super::v1group::V1Group;
use super::super::sec_str::SecureString;

#[doc = "
Implements an entry in a KeePass v1.x database.
"]
pub struct V1Entry {
    /// UUID of the entry
    pub uuid: Uuid,
    /// ID of the group holding the entry
    pub group_id: u32,
    /// Reference to the group holding the entry
    pub group: Option<Rc<RefCell<V1Group>>>,
    /// Used to specify an icon for the entry
    pub image: u32,
    /// Title of the entry
    pub title: String,
    /// URL for the login
    pub url: Option<String>,
    /// Username for the login
    pub username: Option<SecureString>,
    /// Password for the login
    pub password: Option<SecureString>,
    /// Some comment about the entry
    pub comment: Option<String>,
    /// Descripton of the binary content
    pub binary_desc: Option<String>,
    /// ???
    pub binary: Option<Vec<u8>>,
    /// Date of creation
    pub creation: DateTime<Local>,
    /// Date of last modification
    pub last_mod: DateTime<Local>,
    /// Date of last access
    pub last_access: DateTime<Local>,
    /// Expiration date
    pub expire: DateTime<Local>,
}

impl V1Entry {
    /// Don't use this to create an empty entry.
    /// Normally you want to use the API
    /// of V1Kpdb to do this
    pub fn new() -> V1Entry {
        V1Entry { uuid: Uuid::new_v4(),
                  group_id: 0,
                  group: None,
                  image: 0,
                  title: "".to_string(),
                  url: None,
                  username: None,
                  password: None,
                  comment: None,
                  binary_desc: None,
                  binary: None,
                  creation: Local::now(),
                  last_mod: Local::now(),
                  last_access: Local::now(),
                  expire: Local.ymd(2999, 12, 28).and_hms(23, 59, 59),
        }
    }
}

impl PartialEq for V1Entry{
    fn eq(&self, other: &V1Entry) -> bool{
        self.uuid == other.uuid
    }
}

impl Eq for V1Entry {}
