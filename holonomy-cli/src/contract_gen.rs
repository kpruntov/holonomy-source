// @trace TASK-081
use crate::formatter::ColumnInfo;
use serde_json::json;

pub fn generate_contract(dataset_uri: &str, columns: &[ColumnInfo]) -> String {
    let mut columns_array = Vec::new();
    for col in columns {
        let dt = if col.logical_type == "Date" {
            if col.physical_type == "INT32" {
                "date32"
            } else {
                "date64"
            }
        } else if col.logical_type.starts_with("Timestamp") {
            if col.logical_type.contains("MILLIS") {
                "timestamp_ms"
            } else if col.logical_type.contains("MICROS") {
                "timestamp_us"
            } else if col.logical_type.contains("NANOS") {
                "timestamp_ns"
            } else {
                "timestamp_s"
            }
        } else if col.logical_type == "String" || col.logical_type == "UTF8" {
            "string"
        } else {
            match col.physical_type.as_str() {
                "INT32" => "int32",
                "INT64" => "int64",
                "FLOAT" => "float32",
                "DOUBLE" => "float64",
                "BOOLEAN" => "boolean",
                "BYTE_ARRAY" | "FIXED_LEN_BYTE_ARRAY" => "binary",
                _ => "string",
            }
        };

        columns_array.push(json!({
            "name": col.name,
            "type": dt,
            "required": true
        }));
    }

    let policy = json!({
        "name": dataset_uri,
        "version": "1.0",
        "columns": columns_array
    });

    serde_json::to_string_pretty(&policy).unwrap()
}
