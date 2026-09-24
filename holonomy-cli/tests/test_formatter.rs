// @trace TASK-045
use holonomy_cli::formatter::{ColumnInfo, format_ascii_table};

#[test]
fn test_format_ascii_table_empty() {
    let output = format_ascii_table(&[]);
    assert_eq!(output, "No columns found.");
}

#[test]
fn test_format_ascii_table_populated() {
    let columns = vec![
        ColumnInfo {
            name: "id".to_string(),
            physical_type: "INT32".to_string(),
            logical_type: "None".to_string(),
        },
        ColumnInfo {
            name: "created_at".to_string(),
            physical_type: "INT64".to_string(),
            logical_type: "Timestamp".to_string(),
        },
    ];

    let output = format_ascii_table(&columns);
    let expected = "\
+-------------+---------------+----------------------+
| Column Name | Physical Type | Logical Type (Arrow) |
+-------------+---------------+----------------------+
| id          | INT32         | None                 |
| created_at  | INT64         | Timestamp            |
+-------------+---------------+----------------------+
";
    assert_eq!(output, expected);
}
