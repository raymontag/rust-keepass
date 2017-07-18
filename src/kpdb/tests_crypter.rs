#![allow(dead_code)]
use std::fs::File;
use std::io::Read;

use kpdb::parser::HeaderLoadParser;
use kpdb::crypter::Crypter;
use kpdb::v1header::V1Header;
use super::super::sec_str::SecureString;

fn setup(path: String,
         password: Option<String>,
         keyfile: Option<String>)
         -> (Crypter, V1Header, Vec<u8>) {
    let mut file = File::open(path.clone()).unwrap();
    let mut raw: Vec<u8> = vec![];
    let _ = file.read_to_end(&mut raw);
    let encrypted_database = raw.split_off(124);
    let header_parser = HeaderLoadParser::new(raw);
    let header = header_parser.parse_header().unwrap();

    let crypter = Crypter::new(password, keyfile).unwrap();

    (crypter, header, encrypted_database)
}

#[test]
fn test_decrypt_it_w_pass() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_password.kdb".to_string(),
                                                          Some("test".to_string()),
                                                          None);

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_32_b_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_32B_key.kdb".to_string(),
                                                          None,
                                                          Some("test/32Bkey".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_64_b_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_64B_key.kdb".to_string(),
                                                          None,
                                                          Some("test/64Bkey".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_64_b_alt_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_64B_alt_key.kdb".to_string(),
                                                          None,
                                                          Some("test/64Bkey_alt".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_128_b_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_128B_key.kdb".to_string(),
                                                          None,
                                                          Some("test/128Bkey".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_2048_b_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_2048B_key.kdb".to_string(),
                                                          None,
                                                          Some("test/2048Bkey".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}

#[test]
fn test_decrypt_it_w_4096_b_key() {
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_4096B_key.kdb".to_string(),
                                                          None,
                                                          Some("test/4096Bkey".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
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
    let test_content1: Vec<u8> = vec![0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                      0x02, 0x00, 0x09, 0x00, 0x00, 0x00];
    let test_content2: Vec<u8> = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x1F, 0x7C, 0xB5, 0x7E, 0xFB,
                                      0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

    let (mut crypter, header, encrypted_database) = setup("test/test_both.kdb".to_string(),
                                                          Some("test".to_string()),
                                                          Some("test/test_key".to_string()));

    let mut db_tmp: Vec<u8> = vec![];
    match crypter.decrypt_database(&header, encrypted_database) {
        Ok(e) => db_tmp = e,
        Err(_) => assert!(false),
    };

    let db_len = db_tmp.len();
    let test1 = &db_tmp[0..16];
    let test2 = &db_tmp[db_len - 16..db_len];

    assert_eq!(test_content1, test1);
    assert_eq!(test_content2, test2);
}
