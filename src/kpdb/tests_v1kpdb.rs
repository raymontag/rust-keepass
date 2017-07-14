use chrono::{Timelike, Local, TimeZone, Datelike};

use kpdb::v1kpdb::V1Kpdb;
use kpdb::v1error::V1KpdbError;

#[test]
fn test_new() {
    // No keyfile and password should give error as result
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(), None, None);
    match result {
        Ok(_) => assert!(false),
        Err(e) => assert_eq!(e, V1KpdbError::PassErr),
    };

    // Test load at all and parameters
    result = V1Kpdb::new("test/test_both.kdb".to_string(),
                         Some("test".to_string()),
                         Some("test/test_key".to_string()));
    assert!(result.is_ok());
    let mut db = result.ok().unwrap();
    assert_eq!(db.load().is_ok(), true);
    assert_eq!(db.path, "test/test_both.kdb");

    // Test fail of load with wrong password
    result = V1Kpdb::new("test/test_password.kdb".to_string(),
                         Some("tes".to_string()),
                         None);
    assert!(result.is_ok());
    db = result.ok().unwrap();
    match db.load() {
        Ok(_) => assert!(false),
        Err(e) => assert_eq!(e, V1KpdbError::HashErr),
    };
}

#[test]
fn test_save() {
    // if this test fails one has to copy test_password.kdb to test_save.kdb
    let result = V1Kpdb::new("test/test_save.kdb".to_string(), Some("test".to_string()), None);
    assert!(result.is_ok());
    let mut db = result.ok().unwrap();
    match db.load() {
        Ok(_) => {},
        Err(e) => println!("{}", e),
    };
    assert!(db.load().is_ok());
    assert!(db.save(None, None, None).is_ok());
    assert!(db.load().is_ok());
}

#[test]
fn test_create_group_w_title_only() {
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_groups_before = db.header.num_groups;

    assert_eq!(db.create_group("test".to_string(), None, None, None).is_ok(),
               true);

    let mut new_group = db.groups[db.groups.len() - 1].borrow_mut();
    assert_eq!(new_group.title, "test");
    assert_eq!((new_group.expire.year(),
                new_group.expire.month(),
                new_group.expire.day()),
               (2999, 12, 28));
    assert_eq!((new_group.expire.hour(),
                new_group.expire.minute(),
                new_group.expire.second()),
               (23, 59, 59));
    assert_eq!(new_group.image, 0);

    let parent = new_group.parent.as_mut().unwrap();
    assert_eq!(parent.borrow().id, 0);

    assert_eq!(db.header.num_groups, num_groups_before + 1);
}

#[test]
fn test_create_group_w_everything() {
    let mut result = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_groups_before = db.header.num_groups;

    let expire = Local.ymd(2015, 2, 28).and_hms(10, 10, 10);
    let parent = db.groups[1].clone();
    let image = 2;

    assert_eq!(db.create_group("test".to_string(), Some(expire), Some(image), Some(parent))
                 .is_ok(),
               true);

    let mut new_group = db.groups[2].borrow_mut();
    assert_eq!(new_group.title, "test");
    assert_eq!((new_group.expire.year(),
                new_group.expire.month(),
                new_group.expire.day()),
               (2015, 2, 28));
    assert_eq!(new_group.image, 2);

    let parent = new_group.parent.as_mut().unwrap();
    assert_eq!(parent.borrow().title, "12");

    assert_eq!(db.header.num_groups, num_groups_before + 1);
}

#[test]
fn test_create_entry() {
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_entries_before = db.header.num_entries;
    let group = db.groups[0].clone();
    let expire = Local.ymd(2015, 2, 28).and_hms(10, 10, 10);
    db.create_entry(group,
                    "test".to_string(),
                    Some(expire),
                    Some(5),
                    Some("http://foo".to_string()),
                    Some("foo".to_string()),
                    Some("bar".to_string()),
                    Some("foobar".to_string()));

    let mut new_entry = db.entries[db.entries.len() - 1].borrow_mut();
    new_entry.username.as_mut().unwrap().unlock();
    new_entry.password.as_mut().unwrap().unlock();
    assert_eq!(new_entry.title, "test");
    assert_eq!((new_entry.expire.year(),
                new_entry.expire.month(),
                new_entry.expire.day()),
               (2015, 2, 28));
    assert_eq!((new_entry.expire.hour(),
                new_entry.expire.minute(),
                new_entry.expire.second()),
               (10, 10, 10));
    assert_eq!(new_entry.image, 5);
    assert_eq!(new_entry.url.as_ref().unwrap(), "http://foo");
    assert_eq!(new_entry.comment.as_ref().unwrap(), "foo");
    assert_eq!(new_entry.username.as_ref().unwrap().string, "bar");
    assert_eq!(new_entry.password.as_ref().unwrap().string, "foobar");

    assert_eq!(db.header.num_entries, num_entries_before + 1);
}

#[test]
fn test_remove_group() {
    let mut result = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let group = db.groups[2].clone();
    let num_groups_before = db.header.num_groups;
    let num_groups_in_root = db.groups[0].borrow().children.len();
    let num_entries_before = db.header.num_entries;
    let num_entries_in_db = db.entries.len();

    assert_eq!(db.remove_group(group).is_ok(), true);
    assert_eq!(db.groups.len() as u32, num_groups_before - 5);
    assert_eq!(db.header.num_groups, num_groups_before - 5);
    assert_eq!(db.groups[0].borrow().children.len(), num_groups_in_root - 1);
    assert_eq!(db.header.num_entries, num_entries_before - 3);
    assert_eq!(db.entries.len(), num_entries_in_db - 3);
}

#[test]
fn test_remove_group_easy() {
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_groups_before = db.header.num_groups;
    let num_groups_in_root = db.root_group.borrow().children.len();
    let num_entries_before = db.header.num_entries;
    let num_entries_in_db = db.entries.len();

    let group = db.groups[0].clone();
    assert_eq!(db.remove_group(group).is_ok(), true);
    assert_eq!(db.groups.len() as u32, num_groups_before - 1);
    assert_eq!(db.header.num_groups, num_groups_before - 1);
    assert_eq!(db.root_group.borrow().children.len(),
               num_groups_in_root - 1);
    assert_eq!(db.header.num_entries, num_entries_before - 1);
    assert_eq!(db.entries.len(), num_entries_in_db - 1);
}

#[test]
fn test_remove_entry() {
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(),
                                 Some("test".to_string()),
                                 None);
    match result {
        Ok(ref mut e) => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let entry = db.entries[0].clone();
    let num_entries_before = db.header.num_entries;
    let num_entries_in_db = db.entries.len();
    let num_entries_in_group = db.groups[0].borrow().entries.len();

    assert_eq!(db.remove_entry(entry).is_ok(), true);
    assert_eq!(db.header.num_entries, num_entries_before - 1);
    assert_eq!(db.entries.len(), num_entries_in_db - 1);
    assert_eq!(db.groups[0].borrow().entries.len(),
               num_entries_in_group - 1);
}
