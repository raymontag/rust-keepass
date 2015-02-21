#![allow(dead_code)]

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
    assert_eq!(groups[0].borrow().title.as_slice(), "Internet");
    assert_eq!(groups[0].borrow().image, 1);
    assert_eq!(groups[0].borrow().level, 0);
    assert_eq!(groups[0].borrow().creation.year, 0);
    assert_eq!(groups[0].borrow().creation.month, 0);
    assert_eq!(groups[0].borrow().creation.day, 0);

    assert_eq!(groups[1].borrow().id, 2);
    assert_eq!(groups[1].borrow().title.as_slice(), "test");
    assert_eq!(groups[1].borrow().image, 1);
    assert_eq!(groups[1].borrow().level, 0);
    assert_eq!(groups[1].borrow().creation.year, 2014);
    assert_eq!(groups[1].borrow().creation.month, 2);
    assert_eq!(groups[1].borrow().creation.day, 26);
}

#[test]
fn test_parse_entries () {
    let uuid: Vec<u8> = vec![0x0c, 0x31, 0xac, 0x94, 0x23, 0x47, 0x66, 0x36, 
                             0xb8, 0xc0, 0x42, 0x81, 0x5e, 0x5a, 0x14, 0x60];

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

    entries[0].borrow_mut().password.unlock();

    assert_eq!(entries[0].borrow().uuid, uuid);
    assert_eq!(entries[0].borrow().title.as_slice(), "foo");
    assert_eq!(entries[0].borrow().url.as_slice(), "foo");
    assert_eq!(entries[0].borrow().username.as_slice(), "foo");
    assert_eq!(entries[0].borrow().password.string.as_slice(), "DLE\"H<JZ|E");
    assert_eq!(entries[0].borrow().image, 1);
    assert_eq!(entries[0].borrow().group_id, 1);
    assert_eq!(entries[0].borrow().creation.year, 2014);
    assert_eq!(entries[0].borrow().creation.month, 2);
    assert_eq!(entries[0].borrow().creation.day, 26);
}

#[test]
fn test_create_group_tree() {
    let mut db = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                             Some("test".to_string()), None).ok().unwrap();
    assert_eq!(db.load().is_ok(), true);

    let mut group = db.groups[1].borrow_mut();
    let parent = group.parent.as_mut().unwrap().borrow();
    let parent_title = parent.title.as_slice();
    assert_eq!(parent_title, "Internet");
    // assert_eq!(db.groups[2].borrow_mut().parent.as_mut()
    //            .unwrap().borrow().title.as_slice(), "Internet");
    // assert_eq!(db.groups[2].borrow_mut().children[0]
    //            .upgrade().unwrap().borrow().title.as_slice(), "22");
    // assert_eq!(db.groups[2].borrow_mut().children[1]
    //            .upgrade().unwrap().borrow().title.as_slice(), "21");
    // assert_eq!(db.groups[3].borrow_mut().parent.as_mut()
    //            .unwrap().borrow().title.as_slice(), "11");
    // assert_eq!(db.groups[4].borrow_mut().parent.as_mut()
    //            .unwrap().borrow().title.as_slice(), "11");
    // assert_eq!(db.groups[4].borrow_mut().children[0]
    //            .upgrade().unwrap().borrow().title.as_slice(), "32");
    // assert_eq!(db.groups[4].borrow_mut().children[1]
    //            .upgrade().unwrap().borrow().title.as_slice(), "31");
    // assert_eq!(db.groups[5].borrow_mut().parent.as_mut()
    //            .unwrap().borrow().title.as_slice(), "21");
    // assert_eq!(db.groups[6].borrow_mut().parent.as_mut()
    //            .unwrap().borrow().title.as_slice(), "21");

    // assert_eq!(db.entries[0].borrow_mut().group.as_mut()
    //            .unwrap().borrow().title.as_slice(), "Internet");
    // assert_eq!(db.entries[1].borrow_mut().group.as_mut()
    //            .unwrap().borrow().title.as_slice(), "11");
    // assert_eq!(db.entries[2].borrow_mut().group.as_mut()
    //            .unwrap().borrow().title.as_slice(), "12");
    // assert_eq!(db.entries[3].borrow_mut().group.as_mut()
    //            .unwrap().borrow().title.as_slice(), "21");
    // assert_eq!(db.entries[4].borrow_mut().group.as_mut()
    //            .unwrap().borrow().title.as_slice(), "22");
}
