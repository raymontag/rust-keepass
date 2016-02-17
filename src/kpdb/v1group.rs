use std::cell::RefCell;
use std::rc::{Rc, Weak};

use chrono::{DateTime, Local, TimeZone};

use kpdb::GetIndex;
use kpdb::v1entry::V1Entry;
use kpdb::v1error::V1KpdbError;

#[doc = "
Implements a group of a KeePass v1.x database
"]
pub struct V1Group {
    /// Group id unique in the database
    pub id: u32,
    /// Title of the group
    pub title: String,
    /// Number to specify a icon for the group
    pub image: u32,
    /// Level in group tree
    pub level: u16,
    /// Date of creation
    pub creation: DateTime<Local>,
    /// Date of last modification
    pub last_mod: DateTime<Local>,
    /// Date of last access
    pub last_access: DateTime<Local>,
    /// Expiration date for the whole group
    pub expire: DateTime<Local>,
    /// ??
    pub flags: u32,
    /// Pointer to the parent group
    pub parent: Option<Rc<RefCell<V1Group>>>,
    /// Array of weak references to the children
    pub children: Vec<Weak<RefCell<V1Group>>>,
    /// Array of weak references to the entries
    pub entries: Vec<Weak<RefCell<V1Entry>>>, // db: Box<Option<V1Kpdb>>,
}

impl V1Group {
    /// Don't use this to create an empty group.
    /// Normally you want to use the API
    /// of V1Kpdb to do this.
    pub fn new() -> V1Group {
        V1Group {
            id: 0,
            title: "".to_string(),
            image: 0,
            level: 0,
            creation: Local::now(),
            last_mod: Local::now(),
            last_access: Local::now(),
            expire: Local.ymd(2999, 12, 28).and_hms(23, 59, 59),
            flags: 0,
            parent: None,
            children: vec![],
            entries: vec![], // db: box None,
        }
    }

    pub fn drop_weak_child_reference(&mut self,
                                     child: &Rc<RefCell<V1Group>>) -> Result<(), V1KpdbError> {
        let index = try!(self.children.get_index(child));
        let weak_group_reference = self.children.remove(index);
        drop(weak_group_reference);
        Ok(())
    }
    
    pub fn drop_weak_entry_reference(&mut self,
                                     entry: &Rc<RefCell<V1Entry>>) -> Result<(), V1KpdbError> {
        let index = try!(self.entries.get_index(entry));
        let weak_entry_reference = self.entries.remove(index);
        drop(weak_entry_reference);
        Ok(())
    }
}

impl PartialEq for V1Group {
    fn eq(&self, other: &V1Group) -> bool {
        self.id == other.id
    }
}

impl Eq for V1Group {}
