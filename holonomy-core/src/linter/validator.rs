// @trace TASK-081
// @trace TASK-015
// @trace TASK-041
// @trace TASK-033
use arrow::array::Array;
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum LinterError {
    #[error("Missing required column: {0}")]
    MissingColumn(String),
    #[error("Undocumented extra column found: {0}")]
    ExtraColumn(String),
    #[error("Null violation in required column {0} at row {1}")]
    NullViolation(String, usize),
    #[error("Regex violation in column {0} at row {1}")]
    RegexViolation(String, usize),
    #[error("Range violation in column {0} at row {1}")]
    RangeViolation(String, usize),
    #[error("Enum violation in column {0} at row {1}")]
    EnumViolation(String, usize),
    #[error("Type mismatch for column {0}")]
    TypeMismatch(String),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RangeRule {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ColumnPolicy {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub required: bool,
    pub regex: Option<String>,
    pub range: Option<RangeRule>,
    pub allowed_values: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataContract {
    pub name: String,
    pub version: String,
    pub columns: Vec<ColumnPolicy>,
}

pub struct Validator {
    pub contract: DataContract,
    compiled_regexes: HashMap<String, Regex>,
    allowed_sets: HashMap<String, HashSet<String>>,
}

fn expected_data_type(type_str: &str) -> Option<DataType> {
    match type_str.to_lowercase().as_str() {
        "string" | "utf8" => Some(DataType::Utf8),
        "int8" => Some(DataType::Int8),
        "int16" => Some(DataType::Int16),
        "int32" => Some(DataType::Int32),
        "int64" => Some(DataType::Int64),
        "uint8" => Some(DataType::UInt8),
        "uint16" => Some(DataType::UInt16),
        "uint32" => Some(DataType::UInt32),
        "uint64" => Some(DataType::UInt64),
        "float32" => Some(DataType::Float32),
        "float64" => Some(DataType::Float64),
        "boolean" => Some(DataType::Boolean),
        "binary" => Some(DataType::Binary),
        "large_binary" => Some(DataType::LargeBinary),
        "date32" => Some(DataType::Date32),
        "date64" => Some(DataType::Date64),
        "timestamp_ms" => Some(DataType::Timestamp(
            arrow::datatypes::TimeUnit::Millisecond,
            None,
        )),
        "timestamp_s" => Some(DataType::Timestamp(
            arrow::datatypes::TimeUnit::Second,
            None,
        )),
        "timestamp_us" => Some(DataType::Timestamp(
            arrow::datatypes::TimeUnit::Microsecond,
            None,
        )),
        "timestamp_ns" => Some(DataType::Timestamp(
            arrow::datatypes::TimeUnit::Nanosecond,
            None,
        )),
        _ => None,
    }
}

impl Validator {
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let contract: DataContract = serde_json::from_str(json_str).map_err(|e| e.to_string())?;
        let mut compiled_regexes = HashMap::new();
        let mut allowed_sets = HashMap::new();

        for col in &contract.columns {
            if let Some(pattern) = &col.regex {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("Invalid regex for {}: {}", col.name, e))?;
                compiled_regexes.insert(col.name.clone(), re);
            }
            if let Some(av) = &col.allowed_values {
                allowed_sets.insert(col.name.clone(), av.iter().cloned().collect());
            }
        }
        Ok(Self {
            contract,
            compiled_regexes,
            allowed_sets,
        })
    }

    pub fn to_arrow_schema(&self) -> Result<arrow::datatypes::Schema, String> {
        let mut fields = Vec::new();
        for col in &self.contract.columns {
            let dt = expected_data_type(&col.data_type)
                .ok_or_else(|| format!("Unknown type: {}", col.data_type))?;
            fields.push(arrow::datatypes::Field::new(&col.name, dt, !col.required));
        }
        Ok(arrow::datatypes::Schema::new(fields))
    }

    pub fn validate(&self, batch: &RecordBatch) -> Vec<LinterError> {
        let mut errors = Vec::new();
        let schema = batch.schema();
        let batch_cols: HashSet<_> = schema.fields().iter().map(|f| f.name().clone()).collect();
        let contract_cols: HashSet<_> = self
            .contract
            .columns
            .iter()
            .map(|c| c.name.clone())
            .collect();

        // Structural Drift Blocking
        for col in &batch_cols {
            if !contract_cols.contains(col) {
                errors.push(LinterError::ExtraColumn(col.clone()));
            }
        }

        for col_policy in &self.contract.columns {
            if !batch_cols.contains(&col_policy.name) {
                if col_policy.required {
                    errors.push(LinterError::MissingColumn(col_policy.name.clone()));
                }
                continue;
            }

            let col_idx = schema.index_of(&col_policy.name).unwrap();
            let field = schema.field(col_idx);
            let col = batch.column(col_idx);

            // Strict Type Matching
            if let Some(expected_dt) = expected_data_type(&col_policy.data_type) {
                if field.data_type() != &expected_dt {
                    errors.push(LinterError::TypeMismatch(col_policy.name.clone()));
                }
            } else {
                errors.push(LinterError::TypeMismatch(col_policy.name.clone()));
            }

            // Nullability Constraint (Value-level fallback)
            if col_policy.required && col.null_count() > 0 {
                for i in 0..col.len() {
                    if col.is_null(i) {
                        errors.push(LinterError::NullViolation(col_policy.name.clone(), i));
                    }
                }
            }

            // Enum / Allowed Values Enforcement
            if let Some(allowed) = self.allowed_sets.get(&col_policy.name) {
                if let Some(string_array) = col.as_any().downcast_ref::<arrow::array::StringArray>()
                {
                    for i in 0..string_array.len() {
                        if string_array.is_valid(i) && !allowed.contains(string_array.value(i)) {
                            errors.push(LinterError::EnumViolation(col_policy.name.clone(), i));
                        }
                    }
                } else {
                    errors.push(LinterError::TypeMismatch(col_policy.name.clone()));
                }
            }

            // Regex Enforcement
            if let Some(re) = self.compiled_regexes.get(&col_policy.name) {
                if let Some(string_array) = col.as_any().downcast_ref::<arrow::array::StringArray>()
                {
                    for i in 0..string_array.len() {
                        if string_array.is_valid(i) && !re.is_match(string_array.value(i)) {
                            errors.push(LinterError::RegexViolation(col_policy.name.clone(), i));
                        }
                    }
                } else {
                    errors.push(LinterError::TypeMismatch(col_policy.name.clone()));
                }
            }

            // Numeric Range Enforcement
            if let Some(range) = &col_policy.range {
                macro_rules! check_range {
                    ($array_type:ty) => {
                        if let Some(arr) = col.as_any().downcast_ref::<$array_type>() {
                            for i in 0..arr.len() {
                                if arr.is_valid(i) {
                                    let val = arr.value(i) as f64;
                                    if let Some(m) = range.min {
                                        if val < m {
                                            errors.push(LinterError::RangeViolation(
                                                col_policy.name.clone(),
                                                i,
                                            ));
                                        }
                                    }
                                    if let Some(m) = range.max {
                                        if val > m {
                                            errors.push(LinterError::RangeViolation(
                                                col_policy.name.clone(),
                                                i,
                                            ));
                                        }
                                    }
                                }
                            }
                            true
                        } else {
                            false
                        }
                    };
                }
                let checked = check_range!(arrow::array::Int8Array)
                    || check_range!(arrow::array::Int16Array)
                    || check_range!(arrow::array::Int32Array)
                    || check_range!(arrow::array::Int64Array)
                    || check_range!(arrow::array::UInt8Array)
                    || check_range!(arrow::array::UInt16Array)
                    || check_range!(arrow::array::UInt32Array)
                    || check_range!(arrow::array::UInt64Array)
                    || check_range!(arrow::array::Float32Array)
                    || check_range!(arrow::array::Float64Array);
                if !checked {
                    errors.push(LinterError::TypeMismatch(col_policy.name.clone()));
                }
            }
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use crate::linter::validator::{LinterError, Validator};
    use arrow::array::{Float64Array, Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use std::sync::Arc;

    fn get_mock_contract() -> String {
        r#"{
            "name": "EmployeeData",
            "version": "1.0",
            "columns": [
                {
                    "name": "email",
                    "type": "string",
                    "required": true,
                    "regex": "^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$"
                },
                {
                    "name": "role",
                    "type": "string",
                    "required": true,
                    "allowed_values": ["Admin", "User", "Guest"]
                },
                {
                    "name": "age",
                    "type": "int32",
                    "required": false,
                    "range": { "min": 0.0, "max": 120.0 }
                },
                {
                    "name": "salary",
                    "type": "float32",
                    "required": true,
                    "range": { "min": 30000.0 }
                }
            ]
        }"#
        .to_string()
    }

    #[test]
    fn test_validator_exhaustive_errors() {
        let validator = Validator::from_json(&get_mock_contract()).unwrap();

        let email_array = StringArray::from(vec![
            Some("test@example.com"),
            Some("test2@example.com"),
            Some("bad-email"),
        ]);
        let role_array = StringArray::from(vec![Some("Admin"), Some("Hacker"), Some("User")]);
        let age_array = Int32Array::from(vec![Some(25), Some(150), None]);

        // Type Mismatch Test: policy asks for float32, we provide float64
        let salary_array = Float64Array::from(vec![Some(50000.0), Some(20000.0), Some(40000.0)]);

        let unknown_array = Int32Array::from(vec![1, 2, 3]);

        let schema = Arc::new(Schema::new(vec![
            // email is required=true, but we define it as nullable=true in Schema
            Field::new("email", DataType::Utf8, true),
            // role is required=true, so nullable=false in Schema (Correct)
            Field::new("role", DataType::Utf8, false),
            Field::new("age", DataType::Int32, true),
            Field::new("salary", DataType::Float64, true),
            Field::new("undocumented", DataType::Int32, true),
        ]));

        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(email_array),
                Arc::new(role_array),
                Arc::new(age_array),
                Arc::new(salary_array),
                Arc::new(unknown_array),
            ],
        )
        .unwrap();

        let errors = validator.validate(&batch);

        // We expect:
        // 1. Extra column 'undocumented'
        // 2. Regex violation on 'email' at row 2
        // 3. Enum violation on 'role' at row 1 ("Hacker")
        // 4. Range violation on 'age' at row 1 (150 > 120)
        // 5. TypeMismatch on 'salary' (Float64 vs Float32)
        // 6. Range violation on 'salary' at row 1 (20000.0 < 30000.0)

        assert_eq!(errors.len(), 6, "Errors: {:?}", errors);
        assert!(errors.contains(&LinterError::ExtraColumn("undocumented".to_string())));
        assert!(errors.contains(&LinterError::RegexViolation("email".to_string(), 2)));
        assert!(errors.contains(&LinterError::EnumViolation("role".to_string(), 1)));
        assert!(errors.contains(&LinterError::RangeViolation("age".to_string(), 1)));
        assert!(errors.contains(&LinterError::TypeMismatch("salary".to_string())));
        assert!(errors.contains(&LinterError::RangeViolation("salary".to_string(), 1)));
    }

    #[test]
    fn test_validator_missing_column() {
        let validator = Validator::from_json(&get_mock_contract()).unwrap();
        let schema = Arc::new(Schema::new(vec![Field::new("age", DataType::Int32, true)]));
        let age_array = Int32Array::from(vec![Some(25)]);
        let batch = RecordBatch::try_new(schema, vec![Arc::new(age_array)]).unwrap();

        let errors = validator.validate(&batch);
        assert!(errors.contains(&LinterError::MissingColumn("email".to_string())));
        assert!(errors.contains(&LinterError::MissingColumn("role".to_string())));
        assert!(errors.contains(&LinterError::MissingColumn("salary".to_string())));
        // 'age' is not required, so it shouldn't produce a MissingColumn error
        assert!(!errors.contains(&LinterError::MissingColumn("age".to_string())));
    }
}
