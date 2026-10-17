use parquet::encryption::encrypt::FileEncryptionProperties;

#[test]
fn test_compile() {
    let key = vec![0u8; 16];
    let _props = FileEncryptionProperties::builder(key).build().unwrap();
}
