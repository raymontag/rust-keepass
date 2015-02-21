use std::cell::{RefCell};
use std::rc::Rc;

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
    pub path:     String,
    /// Holds the header. Normally you don't need
    /// to manipulate this yourself
    pub header:   V1Header,
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
               keyfile: Option<String>) -> Result<V1Kpdb, V1KpdbError> {
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

        Ok(V1Kpdb { path: path.clone(), header: V1Header::new(),
                    groups: vec![], entries: vec![],
                    root_group: Rc::new(RefCell::new(V1Group::new())),
                    crypter: Crypter::new(path, sec_password,
                                          sec_keyfile),
        })
    }

    /// Decrypt and parse the database.
    pub fn load(&mut self) -> Result<(), V1KpdbError> {
        // First read header and decrypt the database
        try!(self.header.read_header(self.path.clone()));
        let decrypted_database = try!(self.crypter.decrypt_database(&self.header));
        // Next parse groups and entries.
        // pos is needed to remember position after group parsing
        let mut parser = Parser::new(decrypted_database, self.header.num_groups,
                                     self.header.num_entries);
        let (groups, levels) = try!(parser.parse_groups());

        self.groups = groups;
        self.entries = try!(parser.parse_entries());

        parser.delete_decrypted_content();
                
        // Now create the group tree and sort the entries to their groups
        try!(Parser::create_group_tree(self, levels));
        Ok(())
    }
}

