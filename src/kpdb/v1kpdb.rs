use std::cell::RefCell;
use std::rc::Rc;

use chrono::{DateTime, Local};

use kpdb::GetIndex;
use kpdb::crypter::Crypter;
use kpdb::parser::Parser;
use kpdb::v1error::V1KpdbError;
use kpdb::v1group::V1Group;
use kpdb::v1entry::V1Entry;
use kpdb::v1header::V1Header;
use super::super::sec_str::SecureString;

#[doc = "
V1Kpdb implements a KeePass v1.x database. Some notes on the file format:

* Database is encrypted with AES (Twofish currently not supported by this
  module) with a password and/or a keyfile.
* Database holds entries which describes the credentials (username, password
  URL...) and are sorted in groups
* The groups themselves can hold subgroups
* Entries have titles for better identification by the user and expiration
  dates to remind that the password should be changed after some period

TODO:

* saving
* editing
* get rid of unwrap and use more pattern matching
"]
pub struct V1Kpdb {
    /// Filepath of the database
    pub path: String,
    /// Holds the header. Normally you don't need
    /// to manipulate this yourself
    pub header: V1Header,
    /// The groups which hold the entries
    pub groups: Vec<Rc<RefCell<V1Group>>>,
    /// The entries of the whole database
    pub entries: Vec<Rc<RefCell<V1Entry>>>,
    /// A group which holds all groups of level 0
    /// as a subgroup (all groups which are not a
    /// subgroup of another group )
    pub root_group: Rc<RefCell<V1Group>>,
    // Used to de- and encrypt the database
    crypter: Crypter,
}

impl V1Kpdb {
    /// Call this to create a new database instance. You have to call load
    /// to start decrypting and parsing of an existing database!
    /// path is the filepath of the database, password is the database password
    /// and keyfile is the filepath to the keyfile.
    /// password should already lie on the heap as a String type and not &str
    /// as it will be encrypted automatically and otherwise the plaintext
    /// would lie in the memory though
    pub fn new(path: String,
               password: Option<String>,
               keyfile: Option<String>)
               -> Result<V1Kpdb, V1KpdbError> {
        // Password and/or keyfile needed but at least one of both
        if password.is_none() && keyfile.is_none() {
            return Err(V1KpdbError::PassErr);
        }
        let sec_password = match password {
            Some(s) => Some(SecureString::new(s)),
            None => None,
        };
        let sec_keyfile = match keyfile {
            Some(s) => Some(SecureString::new(s)),
            None => None,
        };

        Ok(V1Kpdb {
            path: path.clone(),
            header: V1Header::new(),
            groups: vec![],
            entries: vec![],
            root_group: Rc::new(RefCell::new(V1Group::new())),
            crypter: Crypter::new(path, sec_password, sec_keyfile),
        })
    }

    /// Decrypt and parse the database.
    pub fn load(&mut self) -> Result<(), V1KpdbError> {
        // First read header and decrypt the database
        try!(self.header.read_header(self.path.clone()));
        let decrypted_database = try!(self.crypter
                                          .decrypt_database(&self.header));
        // Next parse groups and entries.
        // pos is needed to remember position after group parsing
        let mut parser = Parser::new(decrypted_database,
                                     self.header.num_groups,
                                     self.header.num_entries);
        let (groups, levels) = try!(parser.parse_groups());

        self.groups = groups;
        self.entries = try!(parser.parse_entries());

        parser.delete_decrypted_content();

        // Now create the group tree and sort the entries to their groups
        try!(Parser::create_group_tree(self, levels));
        Ok(())
    }

    /// Create a new group
    ///
    /// * title: title of the new group
    ///
    /// * expire: expiration date of the group
    ///           None means that the group expires never which itself
    ///           corresponds to the date 28-12-2999 23:59:59
    ///
    /// * image: an image number, used in KeePass and KeePassX for the group
    ///          icon. None means 0
    ///
    /// * parent: a group inside the groups vector which should be the parent in
    ///           the group tree. None means that the root group is the parent
    pub fn create_group(&mut self,
                        title: String,
                        expire: Option<DateTime<Local>>,
                        image: Option<u32>,
                        parent: Option<Rc<RefCell<V1Group>>>)
                        -> Result<(), V1KpdbError> {
        let mut new_id: u32 = 1;
        for group in self.groups.iter() {
            let id = group.borrow().id;
            if id >= new_id {
                new_id = id + 1;
            }
        }

        let new_group = Rc::new(RefCell::new(V1Group::new()));
        new_group.borrow_mut().id = new_id;
        new_group.borrow_mut().title = title;
        new_group.borrow_mut().creation = Local::now();
        new_group.borrow_mut().last_mod = Local::now();
        new_group.borrow_mut().last_access = Local::now();
        match expire {
            Some(s) => new_group.borrow_mut().expire = s,
            None => {} // is 12-28-2999 23:59:59 through V1Group::new
        }
        match image {
            Some(s) => new_group.borrow_mut().image = s,
            None => {} // is 0 through V1Group::new
        }
        match parent {
            Some(s) => {
                let index = try!(self.groups.get_index(&s));
                new_group.borrow_mut().parent = Some(s.clone());
                s.borrow_mut().children.push(Rc::downgrade(&new_group.clone()));
                self.groups.insert(index + 1, new_group);

            }
            None => {
                new_group.borrow_mut().parent = Some(self.root_group
                                                         .clone());
                self.root_group.borrow_mut().children.push(Rc::downgrade(&new_group.clone()));
                self.groups.push(new_group);
            }
        }

        self.header.num_groups += 1;
        Ok(())
    }

    /// Create a new entry
    ///
    /// * group: group which should hold the entry
    ///
    /// * title: title of the new entry
    ///
    /// * expire: expiration date of the group
    ///           None means that the group expires never which itself
    ///           corresponds to the date 28-12-2999 23:59:59
    ///
    /// * image: an image number, used in KeePass and KeePassX for the group
    ///          icon. None means 0
    ///
    /// * url: URL from where the credentials are
    ///
    /// * comment: some free-text-comment about the entry
    ///
    /// * username: username for the URL
    ///
    /// * password: password for the URL
    ///
    /// Note: username and password should be of type String at creation. If you have a
    /// &str which you convert into a String with to_string() the plaintext will remain
    /// in memory as the new created String is a copy of the original &str. If you use
    /// String this function call is a move so that the String remains where it was
    /// created.
    ///
    pub fn create_entry(&mut self,
                        group: Rc<RefCell<V1Group>>,
                        title: String,
                        expire: Option<DateTime<Local>>,
                        image: Option<u32>,
                        url: Option<String>,
                        comment: Option<String>,
                        username: Option<String>,
                        password: Option<String>) {
        // Automatically creates a UUID for the entry
        let new_entry = Rc::new(RefCell::new(V1Entry::new()));
        new_entry.borrow_mut().title = title;
        new_entry.borrow_mut().group = Some(group.clone());
        group.borrow_mut().entries.push(Rc::downgrade(&new_entry.clone()));
        new_entry.borrow_mut().group_id = group.borrow().id;
        new_entry.borrow_mut().creation = Local::now();
        new_entry.borrow_mut().last_mod = Local::now();
        new_entry.borrow_mut().last_access = Local::now();
        match expire {
            Some(s) => new_entry.borrow_mut().expire = s,
            None => {} // is 12-28-2999 23:59:59 through V1Entry::new()
        };
        match image {
            Some(s) => new_entry.borrow_mut().image = s,
            None => {} // is 0 through V1Entry::new()
        }
        new_entry.borrow_mut().url = url;
        new_entry.borrow_mut().comment = comment;
        match username {
            Some(s) => new_entry.borrow_mut().username = Some(SecureString::new(s)),
            None => {}
        };
        match password {
            Some(s) => new_entry.borrow_mut().password = Some(SecureString::new(s)),
            None => {}
        };

        self.entries.push(new_entry);
        self.header.num_entries += 1;
    }

    pub fn remove_group(&mut self, group: Rc<RefCell<V1Group>>) -> Result<(), V1KpdbError> {

        // TODO: Remove critical data
        try!(self.remove_group_from_db(&group));
        try!(self.remove_entries(&group));
        if let Some(ref parent) = group.borrow().parent {
            try!(parent.borrow_mut().drop_weak_child_reference(&group));
            drop(parent);
        }
        try!(self.remove_children(&group));
        Ok(())
    }

    fn remove_group_from_db(&mut self, group: &Rc<RefCell<V1Group>>) -> Result<(), V1KpdbError> {
        let index = try!(self.groups.get_index(group));
        let db_reference = self.groups.remove(index);
        drop(db_reference);
        self.header.num_groups -= 1;
        Ok(())
    }

    fn remove_entry_from_db(&mut self, entry: &Rc<RefCell<V1Entry>>) -> Result<(), V1KpdbError> {
        let index = try!(self.entries.get_index(entry));
        let db_reference = self.entries.remove(index);
        drop(db_reference);
        self.header.num_entries -= 1;
        Ok(())
    }

    fn remove_entries(&mut self, group: &Rc<RefCell<V1Group>>) -> Result<(), V1KpdbError> {
        // Clone needed to prevent thread panning through borrowing
        let entries = group.borrow().entries.clone();
        for entry in entries {
            if let Some(entry_strong) = entry.upgrade() {
                try!(self.remove_entry(entry_strong));
            } else {
                return Err(V1KpdbError::WeakErr);
            }
        }
        Ok(())
    }

    fn remove_children(&mut self, group: &Rc<RefCell<V1Group>>) -> Result<(), V1KpdbError> {
        // Clone needed to prevent thread panning through borrowing
        let children = group.borrow().children.clone();
        for child in children {
            if let Some(child_strong) = child.upgrade() {
                try!(self.remove_group(child_strong));
            } else {
                return Err(V1KpdbError::WeakErr);
            }
        }
        Ok(())
    }

    pub fn remove_entry(&mut self, entry: Rc<RefCell<V1Entry>>) -> Result<(), V1KpdbError> {
        // TODO: Remove critical data
        try!(self.remove_entry_from_db(&entry));

        if let Some(ref group) = entry.borrow().group {
            try!(group.borrow_mut().drop_weak_entry_reference(&entry));
            drop(group);
        }
        Ok(())
    }
}
