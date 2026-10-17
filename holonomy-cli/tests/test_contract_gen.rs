use holonomy_cli::contract_gen::generate_contract;
use holonomy_cli::formatter::ColumnInfo;

#[test]
fn test_generate_contract_output() {
    let columns = vec![
        ColumnInfo {
            name: "id".to_string(),
            physical_type: "INT64".to_string(),
            logical_type: "None".to_string(),
        },
        ColumnInfo {
            name: "email".to_string(),
            physical_type: "BYTE_ARRAY".to_string(),
            logical_type: "String".to_string(),
        },
    ];

    let uri = "s3://test-bucket/my_dataset/";
    let json_output = generate_contract(uri, &columns);

    assert!(json_output.contains("\"name\": \"s3://test-bucket/my_dataset/\""));
    assert!(json_output.contains("\"type\": \"int64\""));
    assert!(json_output.contains("\"type\": \"string\""));
}
