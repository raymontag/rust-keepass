use chrono::{Timelike, Local, TimeZone, Datelike};

use kpdb::v1kpdb::V1Kpdb;
use kpdb::v1error::V1KpdbError;

#[test]
fn test_new() {
    // No keyfile and password should give error as result
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(), None, None);
    match result {
        Ok(_)  => assert!(false),
        Err(e) => assert_eq!(e, V1KpdbError::PassErr),
    };

    // Test load at all and parameters
    result = V1Kpdb::new("test/test_both.kdb".to_string(), Some("test".to_string()),
                         Some("test/test_key".to_string()));
    assert!(result.is_ok());
    let mut db = result.ok().unwrap();
    assert_eq!(db.load().is_ok(), true);
    assert_eq!(db.path.as_slice(), "test/test_both.kdb");

    // Test fail of load with wrong password
    result = V1Kpdb::new("test/test_password.kdb".to_string(), Some("tes".to_string()), None);
    assert!(result.is_ok());
    db = result.ok().unwrap();
    match db.load() {
        Ok(_)  => assert!(false),
        Err(e) => assert_eq!(e, V1KpdbError::HashErr),
    };
}

#[test]
fn test_create_group_w_title_only() {
    let mut result = V1Kpdb::new("test/test_password.kdb".to_string(),
                                 Some("test".to_string()), None);
    match result {
        Ok(ref mut e)  => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_groups_before = db.header.num_groups;
    
    assert_eq!(db.create_group("test".to_string(), None, None, None).is_ok(), true);

    let mut new_group = db.groups[db.groups.len() - 1].borrow_mut();
    assert_eq!(new_group.title, "test");
    assert_eq!((new_group.expire.year(), new_group.expire.month(), new_group.expire.day()),
               (2999, 12, 28));
    assert_eq!((new_group.expire.hour(), new_group.expire.minute(), new_group.expire.second()),
               (23, 59, 59));
    assert_eq!(new_group.image, 0);

    let parent = new_group.parent.as_mut().unwrap();
    assert_eq!(parent.borrow().id, 0);

    assert_eq!(db.header.num_groups, num_groups_before + 1);
}

#[test]
fn test_create_group_w_everything() {
    let mut result = V1Kpdb::new("test/test_parsing.kdb".to_string(),
                                 Some("test".to_string()), None);
    match result {
        Ok(ref mut e)  => assert_eq!(e.load().is_ok(), true),
        Err(_) => assert!(false),
    };
    let mut db = result.unwrap();

    let num_groups_before = db.header.num_groups;
    
    let expire = Local.ymd(2015, 2, 28).and_hms(10,10,10);
    let parent = db.groups[1].clone();
    println!("{}", parent.borrow().title);
    let image = 2;
    
    assert_eq!(db.create_group("test".to_string(), Some(expire), Some(image), Some(parent)).is_ok(), true);
    
    let mut new_group = db.groups[2].borrow_mut();
    assert_eq!(new_group.title, "test");
    assert_eq!((new_group.expire.year(), new_group.expire.month(), new_group.expire.day()),
               (2015, 2, 28));
    assert_eq!(new_group.image, 2);
    
    let parent = new_group.parent.as_mut().unwrap();
    assert_eq!(parent.borrow().title.as_slice(), "12");

    assert_eq!(db.header.num_groups, num_groups_before + 1);
}
