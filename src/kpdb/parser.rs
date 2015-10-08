use libc::{c_void, size_t};
use libc::funcs::posix88::mman;
use std::cell::{RefCell, RefMut};
use std::ptr;
use std::rc::Rc;
use std::str;

use chrono::{DateTime, Local, TimeZone};
use uuid::Uuid;

use kpdb::common::{slice_to_u16, slice_to_u32};
use kpdb::v1error::V1KpdbError;
use kpdb::v1kpdb::V1Kpdb;
use kpdb::v1entry::V1Entry;
use kpdb::v1group::V1Group;
use sec_str::SecureString;
use kpdb::v1header::V1Header;

//Implements a parser to parse a KeePass DB
pub struct Parser {
    pos: usize,
    decrypted_database: Vec<u8>,
    num_groups: u32,
    num_entries: u32,
}

impl Parser {
    pub fn new(decrypted_database: Vec<u8>, num_groups: u32, num_entries: u32) -> Parser {
        Parser { pos: 0usize, decrypted_database: decrypted_database,
                 num_groups: num_groups, num_entries: num_entries}
    }

    // Parse the groups and put them into a vector
    pub fn parse_groups(&mut self)-> Result<(Vec<Rc<RefCell<V1Group>>>, Vec<u16>), V1KpdbError> {
        let mut group_number: u32 = 0;
        let mut levels: Vec<u16> = vec![];
        let mut cur_group = Rc::new(RefCell::new(V1Group::new()));
        let mut groups: Vec<Rc<RefCell<V1Group>>> = vec![];

        let mut field_type: u16;
        let mut field_size: u32;

        while group_number < self.num_groups {
            field_type = try!(slice_to_u16(&self.decrypted_database[self.pos..self.pos + 2]));
            self.pos += 2;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(&self.decrypted_database[self.pos..self.pos + 4]));
            self.pos += 4;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = self.read_group_field(cur_group.borrow_mut(),
                                          field_type, field_size);

            if field_type == 0x0008 {
                levels.push(cur_group.borrow().level);
            } else if field_type == 0xFFFF {
                groups.push(cur_group);
                group_number += 1;
                if group_number == self.num_groups {
                    break;
                };
                cur_group = Rc::new(RefCell::new(V1Group::new()));
            }

            self.pos += field_size as usize;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }

        Ok((groups, levels))
    }

    // Parse the entries and put them into a vector
    pub fn parse_entries(&mut self) -> Result<Vec<Rc<RefCell<V1Entry>>>, V1KpdbError> {
        let mut entry_number: u32 = 0;
        let mut cur_entry = Rc::new(RefCell::new(V1Entry::new()));
        let mut entries: Vec<Rc<RefCell<V1Entry>>> = vec![];

        let mut field_type: u16;
        let mut field_size: u32;

        while entry_number < self.num_entries {
            field_type = try!(slice_to_u16(&self.decrypted_database[self.pos..self.pos + 2]));
            self.pos += 2;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            field_size = try!(slice_to_u32(&self.decrypted_database[self.pos..self.pos + 4]));
            self.pos += 4;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }

            let _ = self.read_entry_field(cur_entry.borrow_mut(),
                                          field_type, field_size);

            if field_type == 0xFFFF {
                entries.push(cur_entry);
                entry_number += 1;
                if entry_number == self.num_entries {
                    break;
                };
                cur_entry = Rc::new(RefCell::new(V1Entry::new()));
            }

            self.pos += field_size as usize;

            if self.pos > self.decrypted_database.len() {
                return Err(V1KpdbError::OffsetErr);
            }
        }

        Ok(entries)
    }

    // Read a group field from the raw data by it's field type
    fn read_group_field(&mut self, mut group: RefMut<V1Group>, field_type: u16, field_size: u32,
                            ) -> Result<(), V1KpdbError> {
        let db_slice = if field_type == 0x0002 {
            &self.decrypted_database[self.pos..self.pos + (field_size - 1) as usize]
        } else {
            &self.decrypted_database[self.pos..self.pos + field_size as usize]
        };

        match field_type {
            0x0001 => group.id = try!(slice_to_u32(db_slice)),
            0x0002 => group.title = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0003 => group.creation = Parser::get_date(db_slice),
            0x0004 => group.last_mod = Parser::get_date(db_slice),
            0x0005 => group.last_access = Parser::get_date(db_slice),
            0x0006 => group.expire = Parser::get_date(db_slice),
            0x0007 => group.image = try!(slice_to_u32(db_slice)),
            0x0008 => group.level = try!(slice_to_u16(db_slice)),
            0x0009 => group.flags = try!(slice_to_u32(db_slice)),
            _ => (),
        }

        Ok(())
    }

    // Read an entry field from the raw data by it's field type
    fn read_entry_field(&mut self, mut entry: RefMut<V1Entry>, field_type: u16, field_size: u32,
                        ) -> Result<(), V1KpdbError> {
        let db_slice = match field_type {
            0x0004 ... 0x0008 | 0x000D =>
                &self.decrypted_database[self.pos..self.pos + (field_size - 1) as usize],
            _ => &self.decrypted_database[self.pos..self.pos + field_size as usize],
        };

        match field_type {
            0x0001 => entry.uuid = Uuid::from_bytes(db_slice).unwrap(),
            0x0002 => entry.group_id = try!(slice_to_u32(db_slice)),
            0x0003 => entry.image = try!(slice_to_u32(db_slice)),
            0x0004 => entry.title = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0005 => entry.url = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0006 => entry.username = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0007 => entry.password = SecureString::new(str::from_utf8(db_slice)
                                                         .unwrap().to_string()),
            0x0008 => entry.comment = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x0009 => entry.creation = Parser::get_date(db_slice),
            0x000A => entry.last_mod = Parser::get_date(db_slice),
            0x000B => entry.last_access = Parser::get_date(db_slice),
            0x000C => entry.expire = Parser::get_date(db_slice),
            0x000D => entry.binary_desc = str::from_utf8(db_slice)
                .unwrap_or("").to_string(),
            0x000E => entry.binary = (0..field_size as usize)
                .map(|i| db_slice[i]).collect(),
            _ => (),
        }

        Ok(())
    }

    // Parse a date. Taken from original KeePass-code
    fn get_date(date_bytes: &[u8]) -> DateTime<Local> {
        let dw1 = date_bytes[0] as i32;
        let dw2 = date_bytes[1] as i32;
        let dw3 = date_bytes[2] as i32;
        let dw4 = date_bytes[3] as i32;
        let dw5 = date_bytes[4] as i32;

        let year = (dw1 << 6) | (dw2 >> 2);
        let month = (((dw2 & 0x03) << 2) | (dw3 >> 6)) as u32;
        let day = ((dw3 >> 1) & 0x1F) as u32;
        let hour = (((dw3 & 0x01) << 4) | (dw4 >> 4)) as u32;
        let minute = (((dw4 & 0x0F) << 2) | (dw5 >> 6)) as u32;
        let second = (dw5 & 0x3F) as u32;

        Local.ymd(year, month, day).and_hms(hour, minute, second)
    }

    // Create the group tree from the level data
    pub fn create_group_tree(db: &mut V1Kpdb,
                             levels: Vec<u16>) -> Result<(), V1KpdbError> {
        if levels[0] != 0 {
            return Err(V1KpdbError::TreeErr);
        }

        for i in (0..db.groups.len()) {
            // level 0 means that the group is not a sub group. Hence add it as a children
            // of the root
            if levels[i] == 0 {
                db.groups[i].borrow_mut().parent = Some(db.root_group.clone());
                db.root_group.borrow_mut()
                    .children.push(Rc::downgrade(&(db.groups[i].clone())));
                continue;
            }

            let mut j = i - 1;
            loop {
                // Find the first group with a lower level than the current.
                // That's the parent
                if levels[j] < levels[i] {
                    if levels[i] - levels[j] != 1 {
                        return Err(V1KpdbError::TreeErr);
                    }
                    db.groups[i].borrow_mut().parent = Some(db.groups[j].clone());
                    db.groups[j].borrow_mut()
                        .children.push(Rc::downgrade(&(db.groups[i].clone())));
                    break;
                }
                // It's not possible that a group which comes after another
                // has a lower level. Hence all following groups which have not
                // level 0 are a subgroup of another.
                if j == 0 {
                    return Err(V1KpdbError::TreeErr);
                }
                j -= 1;
            }
        }

        // Sort entries to their groups
        // iter is secure as it is just obfuscated
        // pointer arithmetic to the entries vector
        for e in db.entries.iter() {
            for g in db.groups.iter() {
                if e.borrow().group_id == g.borrow().id {
                    g.borrow_mut().entries.push(Rc::downgrade(&e.clone()));
                    e.borrow_mut().group = Some(g.clone());
                }
            }
        }

        Ok(())
    }

    pub fn delete_decrypted_content(&mut self) {
        // Zero out raw data as it's not needed anymore
        unsafe { ptr::write_bytes(self.decrypted_database.as_ptr() as *mut c_void, 0u8,
                                  self.decrypted_database.len());
                 mman::munlock(self.decrypted_database.as_ptr() as *const c_void,
                               self.decrypted_database.len() as size_t); }
    }

    pub fn parse_header(header_bytes: &[u8]) -> Result<V1Header, V1KpdbError> {
        // A static method to parse a KeePass v1.x header

        let mut final_randomseed: Vec<u8> = vec![];
        let mut iv: Vec<u8> = vec![];
        let mut contents_hash: Vec<u8> = vec![];
        let mut transf_randomseed: Vec<u8> = vec![];

        let signature1 = try!(slice_to_u32(&header_bytes[0..4]));
        let signature2 = try!(slice_to_u32(&header_bytes[4..8]));
        let enc_flag = try!(slice_to_u32(&header_bytes[8..12]));
        let version = try!(slice_to_u32(&header_bytes[12..16]));
        final_randomseed.extend(&header_bytes[16..32]);
        iv.extend(&header_bytes[32..48]);
        let num_groups = try!(slice_to_u32(&header_bytes[48..52]));
        let num_entries = try!(slice_to_u32(&header_bytes[52..56]));
        contents_hash.extend(&header_bytes[56..88]);
        transf_randomseed.extend(&header_bytes[88..120]);
        let key_transf_rounds = try!(slice_to_u32(&header_bytes[120..124]));


        Ok(V1Header { signature1: signature1,
                      signature2: signature2,
                      enc_flag: enc_flag,
                      version: version,
                      final_randomseed: final_randomseed,
                      iv: iv,
                      num_groups: num_groups,
                      num_entries: num_entries,
                      contents_hash: contents_hash,
                      transf_randomseed: transf_randomseed,
                      key_transf_rounds: key_transf_rounds })
    }
}

impl Drop for Parser {
    fn drop(&mut self) {
        self.delete_decrypted_content();
    }
}
