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

