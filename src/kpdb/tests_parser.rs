#![allow(dead_code, unused_imports)]
use std::io::{Seek, SeekFrom, Read, Write};
use std::fs::File;

use chrono::Datelike;
use uuid::Uuid;

use kpdb::crypter::Crypter;
use kpdb::parser::{HeaderLoadParser, LoadParser,SaveParser};
use kpdb::v1header::V1Header;
use kpdb::v1kpdb::V1Kpdb;
use super::super::sec_str::SecureString;

fn setup(path: String, password: Option<String>, keyfile: Option<String>) -> LoadParser {
    let mut file = File::open(path.clone()).unwrap();
    let mut raw: Vec<u8> = vec![];
    let _ = file.read_to_end(&mut raw);
    let encrypted_database = raw.split_off(124);
    let header_parser = HeaderLoadParser::new(raw);
    let header = header_parser.parse_header().unwrap();

    let mut crypter = Crypter::new(password, keyfile).unwrap();

    let mut decrypted_database: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => {
            decrypted_database = e;
        }
        Err(_) => assert!(false),
    };

    LoadParser::new(decrypted_database, header.num_groups, header.num_entries)
}

#[test]
fn test_parse_groups() {
    let mut parser = setup("test/test_password.kdb".to_string(),
                           Some("test".to_string()),
                           None);

    let mut groups = vec![];
    match parser.parse_groups() {
        Ok((e, _)) => {
            groups = e;
        }
        Err(_) => assert!(false),
    }

    assert_eq!(groups[0].borrow().id, 1);
    assert_eq!(groups[0].borrow().title, "Internet");
    assert_eq!(groups[0].borrow().image, 1);
    assert_eq!(groups[0].borrow().level, 0);

    assert_eq!(groups[1].borrow().id, 2);
    assert_eq!(groups[1].borrow().title, "test");
    assert_eq!(groups[1].borrow().image, 1);
    assert_eq!(groups[1].borrow().level, 0);
    assert_eq!(groups[1].borrow().creation.year(), 2014);
    assert_eq!(groups[1].borrow().creation.month(), 2);
    assert_eq!(groups[1].borrow().creation.day(), 26);
}

#[test]
fn test_parse_entries() {
    let uuid = Uuid::from_bytes(&[0x0c, 0x31, 0xac, 0x94, 0x23, 0x47, 0x66, 0x36, 0xb8, 0xc0,
                                  0x42, 0x81, 0x5e, 0x5a, 0x14, 0x60])
                   .unwrap();

    let mut parser = setup("test/test_password.kdb".to_string(),
                           Some("test".to_string()),
                           None);

    match parser.parse_groups() {
        Ok((_, _)) => {}
        Err(_) => assert!(false),
    };

    let mut entries = vec![];
    match parser.parse_entries() {
        Ok(e) => {
            entries = e;
        }
        Err(_) => assert!(false),
    }

    entries[0].borrow_mut().username.as_mut().unwrap().unlock();
    entries[0].borrow_mut().password.as_mut().unwrap().unlock();

    assert_eq!(entries[0].borrow().uuid, uuid);
    assert_eq!(entries[0].borrow().title, "foo");
    assert_eq!(entries[0].borrow().url, Some("foo".to_string()));
    assert_eq!(entries[0].borrow().username.as_ref().unwrap().string, "foo");
    assert_eq!(entries[0].borrow().password.as_ref().unwrap().string,
               "DLE\"H<JZ|E");
    assert_eq!(entries[0].borrow().image, 1);
    assert_eq!(entries[0].borrow().group_id, 1);
    assert_eq!(entries[0].borrow().creation.year(), 2014);
    assert_eq!(entries[0].borrow().creation.month(), 2);
    assert_eq!(entries[0].borrow().creation.day(), 26);
}

fn get_parent_title(index: usize, db: &V1Kpdb) -> String {
    let mut group = db.groups[index].borrow_mut();
    let parent = group.parent.as_mut().unwrap().borrow();
    parent.title.clone()
}

fn get_children_title(parent_index: usize, children_index: usize, db: &V1Kpdb) -> String {
    let group = db.groups[parent_index].borrow_mut();
    let children_ref = group.children[children_index].upgrade().unwrap();
    let children = children_ref.borrow();
    children.title.clone()
}

fn get_entry_parent_title(index: usize, db: &V1Kpdb) -> String {
    let mut entry = db.entries[index].borrow_mut();
    let group = entry.group.as_mut().unwrap().borrow();
    group.title.clone()
}
#[test]
fn test_create_group_tree() {
    let mut db = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                             Some("test".to_string()),
                             None)
                     .ok()
                     .unwrap();
    assert_eq!(db.load().is_ok(), true);

    assert_eq!(get_parent_title(1, &db), "Internet");
    assert_eq!(get_parent_title(2, &db), "Internet");
    assert_eq!(get_children_title(2, 0, &db), "22");
    assert_eq!(get_children_title(2, 1, &db), "21");
    assert_eq!(get_parent_title(3, &db), "11");
    assert_eq!(get_parent_title(4, &db), "11");
    assert_eq!(get_children_title(4, 0, &db), "32");
    assert_eq!(get_children_title(4, 1, &db), "31");
    assert_eq!(get_parent_title(5, &db), "21");
    assert_eq!(get_parent_title(6, &db), "21");

    assert_eq!(get_entry_parent_title(0, &db), "Internet");
    assert_eq!(get_entry_parent_title(1, &db), "11");
    assert_eq!(get_entry_parent_title(2, &db), "12");
    assert_eq!(get_entry_parent_title(3, &db), "21");
    assert_eq!(get_entry_parent_title(4, &db), "22");
}


#[test]
fn test_read_header() {
    let mut file = File::open("test/test_password.kdb".to_string()).unwrap();
    let mut raw: Vec<u8> = vec![];
    let _ = file.read_to_end(&mut raw);
    let _ = raw.split_off(124);
    let header_parser = HeaderLoadParser::new(raw);

    let mut header = V1Header::new();
    match header_parser.parse_header() {
        Ok(h) => {
            header = h;
        }
        Err(_) => assert!(false),
    }

    assert_eq!(header.signature1, 0x9AA2D903u32);
    assert_eq!(header.signature2, 0xB54BFB65u32);
    assert_eq!(header.enc_flag & 2, 2);
    assert_eq!(header.version, 0x00030002u32);
    assert_eq!(header.num_groups, 2);
    assert_eq!(header.num_entries, 1);
    assert_eq!(header.key_transf_rounds, 150000);
    assert_eq!(header.final_randomseed[0], 0xB0u8);
    assert_eq!(header.final_randomseed[15], 0xE1u8);
    assert_eq!(header.iv[0], 0x15u8);
    assert_eq!(header.iv[15], 0xE5u8);
    assert_eq!(header.content_hash[0], 0xCBu8);
    assert_eq!(header.content_hash[15], 0x4Eu8);
    assert_eq!(header.transf_randomseed[0], 0x69u8);
    assert_eq!(header.transf_randomseed[15], 0x9Fu8);
}

#[test]
fn test_prepare_save() {
    let test_1 = vec![0x01, 0x00, 0x04, 0x00,
                      0x00, 0x00, 0x01, 0x00,
                      0x00, 0x00, 0x02, 0x00,
                      0x09, 0x00, 0x00, 0x00,
                      0x49, 0x6e, 0x74, 0x65,
                      0x72, 0x6e, 0x65, 0x74,
                      0x00, 0x03, 0x00, 0x05,
                      0x00, 0x00, 0x00, 0x1f,
                      0x80, 0xae, 0xf4, 0x64,
                      ];
    let test_2 = vec![0x00, 0x00, 0x00, 0x01,
                      0x00, 0x00, 0x00, 0x08,
                      0x00, 0x02, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x09,
                      0x00, 0x04, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0xff, 0xff, 0x00,
                      0x00, 0x00, 0x00, 0x01,
                      0x00, 0x04, 0x00, 0x00,
                      ];
    let test_3 = vec![0x05, 0x00, 0x05, 0x00,
                      0x00, 0x00, 0x1f, 0x79,
                      0x09, 0x71, 0x08, 0x06,
                      0x00, 0x05, 0x00, 0x00,
                      0x00, 0x2e, 0xdf, 0x39,
                      0x7e, 0xfb, 0x07, 0x00,
                      0x04, 0x00, 0x00, 0x00,
                      0x01, 0x00, 0x00, 0x00,
                      0x08, 0x00, 0x02, 0x00,
                      ];
    let test_4 = vec![0x31, 0x31, 0x00, 0x03,
                      0x00, 0x05, 0x00, 0x00,
                      0x00, 0x1f, 0x79, 0x09,
                      0x71, 0x04, 0x04, 0x00,
                      0x05, 0x00, 0x00, 0x00,
                      0x1f, 0x79, 0x09, 0x71,
                      0x0e, 0x05, 0x00, 0x05,
                      0x00, 0x00, 0x00, 0x1f,
                      0x79, 0x09, 0x71, 0x04,
                      ];
    
    let mut db = V1Kpdb::new("test/test_save.kdb".to_string(),
                             Some("test".to_string()),
                             None)
                     .ok()
                     .unwrap();
    assert_eq!(db.load().is_ok(), true);

    let mut parser = SaveParser::new();
    parser.prepare(&db);

    println!("{:?}", parser.database);
    assert_eq!(test_1[..], parser.database[0..36]);
    assert_eq!(test_2[..], parser.database[72..108]);
    assert_eq!(test_3[..], parser.database[144..180]);
    assert_eq!(test_4[..], parser.database[216..252]);
}

