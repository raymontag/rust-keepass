#![allow(dead_code, unused_imports)]

use chrono::Datelike;
use uuid::Uuid;

use kpdb::crypter::Crypter;
use kpdb::parser::Parser;
use kpdb::v1header::V1Header;
use kpdb::v1kpdb::V1Kpdb;
use super::super::sec_str::SecureString;

fn setup(path: String, password: Option<SecureString>,
         keyfile: Option<SecureString>) -> Parser {
    let mut header = V1Header::new();
    let _ = header.read_header(path.clone());
    let mut crypter = Crypter::new(path, password, keyfile);

    let mut decrypted_database: Vec<u8> = vec![];
    match crypter.decrypt_database(&header) {
        Ok(e)  => { decrypted_database = e;},
        Err(_) => assert!(false),
    };

    Parser::new(decrypted_database, header.num_groups, header.num_entries)
}

#[test]
fn test_parse_groups () {
    let mut parser = setup("test/test_password.kdb".to_string(),
                           Some(SecureString::new("test".to_string())),
                           None);
                                    
    let mut groups = vec![];
    match parser.parse_groups() {
        Ok((e, _)) => { groups = e; }, 
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
fn test_parse_entries () {
    let uuid = Uuid::from_bytes(&[0x0c, 0x31, 0xac, 0x94, 0x23, 0x47, 0x66, 0x36, 
                                  0xb8, 0xc0, 0x42, 0x81, 0x5e, 0x5a, 0x14, 0x60]).unwrap();

    let mut parser = setup("test/test_password.kdb".to_string(),
                           Some(SecureString::new("test".to_string())),
                           None);

    match parser.parse_groups() {
        Ok((_, _)) => {}, 
        Err(_) => assert!(false),
    };
    
    let mut entries = vec![];
    match parser.parse_entries() {
        Ok(e)  => { entries = e; }, 
        Err(_) => assert!(false),
    }

    entries[0].borrow_mut().username.as_mut().unwrap().unlock();
    entries[0].borrow_mut().password.as_mut().unwrap().unlock();
    
    assert_eq!(entries[0].borrow().uuid, uuid);
    assert_eq!(entries[0].borrow().title, "foo");
    assert_eq!(entries[0].borrow().url, Some("foo".to_string()));
    assert_eq!(entries[0].borrow().username.as_ref().unwrap().string, "foo");
    assert_eq!(entries[0].borrow().password.as_ref().unwrap().string, "DLE\"H<JZ|E");
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

fn get_children_title(parent_index: usize, children_index: usize,
                      db: &V1Kpdb) -> String {
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
                             Some("test".to_string()), None).ok().unwrap();
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
