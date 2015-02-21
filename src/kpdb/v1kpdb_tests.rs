use super::v1kpdb::V1Kpdb;
use super::v1error::V1KpdbError;
use super::v1header::V1Header;
use sec_str::SecureString;

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

    match db.password {
        Some(mut s) => {assert_eq!(s.string.as_slice(), "\0\0\0\0");
                        s.unlock();
                        assert_eq!(s.string.as_slice(), "test")},
        None => assert!(false),
    };
    match db.keyfile {
        Some(mut s) => {assert_eq!(s.string.as_slice(), "\0\0\0\0\0\0\0\0\0\0\0\0\0");
                        s.unlock();
                        assert_eq!(s.string.as_slice(), "test/test_key")},
        None => assert!(false),
    };
    
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
fn test_passwordkey() {
    let testkey = vec![0x04, 0xE7, 0x22, 0xF6,
                       0x17, 0x1D, 0x5A, 0x4D,
                       0xE9, 0xBE, 0x7D, 0x36,
                       0x74, 0xB1, 0x5F, 0x83,
                       0xA7, 0xD4, 0x22, 0x67,
                       0xAF, 0x38, 0x24, 0x05,
                       0xDA, 0x9A, 0xA6, 0x09,
                       0x3E, 0x63, 0xC8, 0x70];

    let mut header = V1Header::new();
    let _ = header.read_header("test/test_password.kdb".to_string());
    let mut sec_str = SecureString::new("test".to_string());
    let result = V1Kpdb::get_passwordkey(&mut sec_str);
    assert!(result.is_ok());
    let masterkey = result.ok().unwrap();

    let result = V1Kpdb::transform_key(masterkey, &header);
    assert!(result.is_ok());
    let finalkey = result.ok().unwrap();
    
    assert_eq!(finalkey, testkey);
}

#[test]
fn test_keyfilekey() {
    let test_hash1 = vec![0x97, 0x57, 0xC1, 0xFB,
                          0x2F, 0xFB, 0x2B, 0xEA,
                          0x15, 0x82, 0x2B, 0x84,
                          0xF0, 0xBD, 0x50, 0xCF,
                          0xCC, 0x57, 0xE6, 0xF5,
                          0x56, 0xE0, 0x1D, 0x92,
                          0xF7, 0x38, 0xEF, 0x72,
                          0xB5, 0xC5, 0xA2, 0xEF];
    let test_hash2 = vec![0xB7, 0x4B, 0xCE, 0x14,
                          0x8B, 0xB9, 0xEF, 0xA2,
                          0xA3, 0xBE, 0xFC, 0xEC,
                          0xFD, 0xC5, 0x45, 0xFB,
                          0x4F, 0x5B, 0xF1, 0x38,
                          0x57, 0xF5, 0xC5, 0x6F,
                          0xB2, 0x6C, 0x11, 0x0F,
                          0x30, 0x3B, 0x48, 0x95];
    let test_hash3 = vec![0xA0, 0x6B, 0xB1, 0xE0,
                          0xDD, 0x95, 0x66, 0x92,
                          0x93, 0xF9, 0xF3, 0xBD,
                          0xC0, 0x6B, 0x40, 0x98,
                          0x48, 0x80, 0x08, 0xE0,
                          0x6E, 0x91, 0xA4, 0x6C,
                          0xEE, 0xBA, 0x2E, 0x25,
                          0xF7, 0xE7, 0x20, 0xA7];
    let test_hash4 = vec![0x35, 0x6F, 0xCD, 0x45,
                          0x2D, 0x70, 0xB8, 0xDA,
                          0x89, 0x8C, 0x9D, 0x16,
                          0x06, 0xAF, 0x62, 0x08,
                          0x71, 0xEB, 0xBD, 0x2D,
                          0x10, 0x45, 0x59, 0xB8,
                          0x75, 0x3B, 0x8A, 0xD5,
                          0x15, 0xAC, 0xBE, 0x4D];
    let test_hash5 = vec![0xB3, 0x61, 0x48, 0x08,
                          0xD3, 0xAE, 0xC9, 0x60,
                          0x97, 0x82, 0xED, 0x52,
                          0x59, 0x82, 0x89, 0x1D,
                          0x5F, 0xFA, 0x23, 0xC7,
                          0xCE, 0x8A, 0x00, 0x4F,
                          0x5D, 0x64, 0x27, 0xDD,
                          0x4F, 0x44, 0xAF, 0x8B];
    let test_hash6 = vec![0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF];

    let mut key1 = SecureString::new("test/32Bkey".to_string());
    let mut key2 = SecureString::new("test/64Bkey".to_string());
    let mut key3 = SecureString::new("test/128Bkey".to_string());
    let mut key4 = SecureString::new("test/2048Bkey".to_string());
    let mut key5 = SecureString::new("test/4096Bkey".to_string());
    let mut key6 = SecureString::new("test/64Bkey_alt".to_string());

    match V1Kpdb::get_keyfilekey(&mut key1) {
        Ok(e)  => assert_eq!(e, test_hash1),
        Err(_) => assert!(false),
    }


    match V1Kpdb::get_keyfilekey(&mut key2) {
        Ok(e)  => assert_eq!(e, test_hash2),
        Err(_) => assert!(false),
    }

    match V1Kpdb::get_keyfilekey(&mut key3) {
        Ok(e)  => assert_eq!(e, test_hash3),
        Err(_) => assert!(false),
    }

    match V1Kpdb::get_keyfilekey(&mut key4) {
        Ok(e)  => assert_eq!(e, test_hash4),
        Err(_) => assert!(false),
    }

    match V1Kpdb::get_keyfilekey(&mut key5) {
        Ok(e)  => assert_eq!(e, test_hash5),
        Err(_) => assert!(false),
    }

    match V1Kpdb::get_keyfilekey(&mut key6) {
        Ok(e)  => assert_eq!(e, test_hash6),
        Err(_) => assert!(false),
    }
}

#[test]
fn test_decrypt_it_w_pass() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00,
                                      0x00, 0x00, 0x01, 0x00,
                                      0x00, 0x00, 0x02, 0x00,
                                      0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00,
                                      0x00, 0x1F, 0x7C, 0xB5,
                                      0x7E, 0xFB, 0xFF, 0xFF,
                                      0x00, 0x00, 0x00, 0x00];

    let mut header = V1Header::new();
    let _ = header.read_header("test/test_password.kdb".to_string());
    let mut password = Some(SecureString::new("test".to_string()));
    let mut keyfile = None;
    
    let mut db_tmp: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                   &mut password, &mut keyfile,
                                   &header) {
        Ok(e)  => {db_tmp = e},
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00,
                                      0x00, 0x00, 0x01, 0x00,
                                      0x00, 0x00, 0x02, 0x00,
                                      0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00,
                                      0x00, 0x1F, 0x7C, 0xB5,
                                      0x7E, 0xFB, 0xFF, 0xFF,
                                      0x00, 0x00, 0x00, 0x00];

    let mut header = V1Header::new();
    let _ = header.read_header("test/test_keyfile.kdb".to_string());
    let mut password = None;
    let mut keyfile = Some(SecureString::new("test/test_key".to_string()));
    
    let mut db_tmp: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_keyfile.kdb".to_string(),
                                   &mut password, &mut keyfile,
                                   &header) {
        Ok(e)  => {db_tmp = e},
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_both() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00,
                                      0x00, 0x00, 0x01, 0x00,
                                      0x00, 0x00, 0x02, 0x00,
                                      0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00,
                                      0x00, 0x1F, 0x7C, 0xB5,
                                      0x7E, 0xFB, 0xFF, 0xFF,
                                      0x00, 0x00, 0x00, 0x00];

    let mut header = V1Header::new();
    let _ = header.read_header("test/test_both.kdb".to_string());
    let mut password = Some(SecureString::new("test".to_string()));
    let mut keyfile = Some(SecureString::new("test/test_key".to_string()));
    
    let mut db_tmp: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_both.kdb".to_string(),
                                   &mut password, &mut keyfile,
                                   &header) {
        Ok(e)  => {db_tmp = e},
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_parse_groups () {
    let mut header = V1Header::new();
    let _ = header.read_header("test/test_password.kdb".to_string());
    let sec_str = SecureString::new("test".to_string());
    let mut keyfile = None;
    let mut decrypted_database: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                   &mut Some(sec_str), &mut keyfile,
                                   &header) {
        Ok(e)  => { decrypted_database = e;},
        Err(_) => assert!(false),
    };
    
    let mut groups = vec![];
    match V1Kpdb::parse_groups(&header, &decrypted_database, &mut 0usize) {
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

    let mut header = V1Header::new();
    let _ = header.read_header("test/test_password.kdb".to_string());
    let sec_str = SecureString::new("test".to_string());
    let mut keyfile = None;
    let mut decrypted_database: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_password.kdb".to_string(),
                                   &mut Some(sec_str), &mut keyfile,
                                   &header) {
        Ok(e)  => { decrypted_database = e;},
        Err(_) => assert!(false),
    };

    let mut entries = vec![];
    match V1Kpdb::parse_entries(&header, &decrypted_database, &mut 138usize) {
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
    
    let mut header = V1Header::new();
    let _ = header.read_header("test/test_parsing.kdb".to_string());
    let sec_str = SecureString::new("test".to_string());
    let mut keyfile = None;
    let mut decrypted_database: Vec<u8> = vec![];
    match V1Kpdb::decrypt_database("test/test_parsing.kdb".to_string(),
                                   &mut Some(sec_str), &mut keyfile,
                                   &header) {
        Ok(e)  => { decrypted_database = e;},
        Err(_) => assert!(false),
    };

    let mut pos = 0usize;

    let mut groups = vec![];
    let mut levels = vec![];
    match V1Kpdb::parse_groups(&header, &decrypted_database, &mut pos) {
        Ok((e, l)) => { groups = e;
                        levels = l;}, 
        Err(_) => assert!(false),
    }
    db.groups = groups;

    let mut pos_cpy = pos;
    let mut entries = vec![];
    match V1Kpdb::parse_entries(&header, &decrypted_database, &mut pos_cpy) {
        Ok(e)  => { entries = e; }, 
        Err(_) => assert!(false),
    }
    db.entries = entries;

    assert_eq!(V1Kpdb::create_group_tree(&mut db, levels).is_ok(), true);


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
