// @trace TASK-012
use crate::ingestion::s3_client::{Predicate, PredicateValue};
use arrow::{
    array::{
        Array, BooleanArray, Int32Array, Int64Array, StringArray, StringBuilder, new_null_array,
    },
    compute::filter,
    datatypes::DataType,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GovernanceError {
    #[error("Filtering failed: {0}")]
    FilterError(String),
    #[error("Masking failed: {0}")]
    MaskingError(String),
    #[error("Sampling failed: {0}")]
    SamplingError(String),
}

pub enum MaskingPolicy {
    Nullify,
    Hash,
    DynamicString {
        prefix_len: usize,
        mask_char: char,
        domain_suffix: String,
    },
}

pub struct GovernanceEngine;

impl GovernanceEngine {
    /// Applies SIMD-accelerated row-level security (RLS) filtering to an Arrow Array.
    pub fn apply_rls(
        array: &dyn Array,
        predicate_mask: &BooleanArray,
    ) -> Result<std::sync::Arc<dyn Array>, GovernanceError> {
        filter(array, predicate_mask).map_err(|e| GovernanceError::FilterError(e.to_string()))
    }

    pub fn evaluate_filter(
        array: &dyn Array,
        predicate: &Predicate,
    ) -> Result<BooleanArray, GovernanceError> {
        use arrow::compute::kernels::cmp;

        match predicate {
            Predicate::Eq { value, .. } => match value {
                PredicateValue::String(s) => {
                    let scalar_array =
                        build_scalar_string_array(s.as_str(), array.data_type(), array.len())
                            .map_err(GovernanceError::FilterError)?;
                    cmp::eq(&array, &scalar_array)
                        .map_err(|e| GovernanceError::FilterError(e.to_string()))
                }
                PredicateValue::Int64(v) => {
                    if array.data_type() == &arrow::datatypes::DataType::Int32 {
                        let scalar_array = Int32Array::from(vec![*v as i32; array.len()]);
                        cmp::eq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else if array.data_type() == &arrow::datatypes::DataType::Date32 {
                        let scalar_array =
                            arrow::array::Date32Array::from(vec![*v as i32; array.len()]);
                        cmp::eq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else {
                        let scalar_array = Int64Array::from(vec![*v; array.len()]);
                        cmp::eq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    }
                }
            },
            Predicate::Neq { value, .. } => match value {
                PredicateValue::String(s) => {
                    let scalar_array =
                        build_scalar_string_array(s.as_str(), array.data_type(), array.len())
                            .map_err(GovernanceError::FilterError)?;
                    cmp::neq(&array, &scalar_array)
                        .map_err(|e| GovernanceError::FilterError(e.to_string()))
                }
                PredicateValue::Int64(v) => {
                    if array.data_type() == &arrow::datatypes::DataType::Int32 {
                        let scalar_array = Int32Array::from(vec![*v as i32; array.len()]);
                        cmp::neq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else if array.data_type() == &arrow::datatypes::DataType::Date32 {
                        let scalar_array =
                            arrow::array::Date32Array::from(vec![*v as i32; array.len()]);
                        cmp::neq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else {
                        let scalar_array = Int64Array::from(vec![*v; array.len()]);
                        cmp::neq(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    }
                }
            },
            Predicate::Gt { value, .. } => match value {
                PredicateValue::String(s) => {
                    let scalar_array =
                        build_scalar_string_array(s.as_str(), array.data_type(), array.len())
                            .map_err(GovernanceError::FilterError)?;
                    cmp::gt(&array, &scalar_array)
                        .map_err(|e| GovernanceError::FilterError(e.to_string()))
                }
                PredicateValue::Int64(v) => {
                    if array.data_type() == &arrow::datatypes::DataType::Int32 {
                        let scalar_array = Int32Array::from(vec![*v as i32; array.len()]);
                        cmp::gt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else if array.data_type() == &arrow::datatypes::DataType::Date32 {
                        let scalar_array =
                            arrow::array::Date32Array::from(vec![*v as i32; array.len()]);
                        cmp::gt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else {
                        let scalar_array = Int64Array::from(vec![*v; array.len()]);
                        cmp::gt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    }
                }
            },
            Predicate::Lt { value, .. } => match value {
                PredicateValue::String(s) => {
                    let scalar_array =
                        build_scalar_string_array(s.as_str(), array.data_type(), array.len())
                            .map_err(GovernanceError::FilterError)?;
                    cmp::lt(&array, &scalar_array)
                        .map_err(|e| GovernanceError::FilterError(e.to_string()))
                }
                PredicateValue::Int64(v) => {
                    if array.data_type() == &arrow::datatypes::DataType::Int32 {
                        let scalar_array = Int32Array::from(vec![*v as i32; array.len()]);
                        cmp::lt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else if array.data_type() == &arrow::datatypes::DataType::Date32 {
                        let scalar_array =
                            arrow::array::Date32Array::from(vec![*v as i32; array.len()]);
                        cmp::lt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    } else {
                        let scalar_array = Int64Array::from(vec![*v; array.len()]);
                        cmp::lt(&array, &scalar_array)
                            .map_err(|e| GovernanceError::FilterError(e.to_string()))
                    }
                }
            },
        }
    }

    /// Applies Deterministic Row Sampling.
    /// Creates a boolean mask deterministically based on a seed to enforce sampling caps
    /// (e.g., return roughly X% of rows). This mask can then be used with `apply_rls`.
    pub fn create_sampling_mask(
        row_count: usize,
        selectivity_percentage: f64,
        seed: u64,
    ) -> BooleanArray {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = (selectivity_percentage * u32::MAX as f64) as u32;

        let mask: Vec<bool> = (0..row_count)
            .map(|_| rng.random::<u32>() < threshold)
            .collect();
        BooleanArray::from(mask)
    }

    /// Applies Contextual Data Masking to a StringArray based on the provided policy.
    pub fn mask_string_column(
        array: &StringArray,
        policy: MaskingPolicy,
    ) -> Result<std::sync::Arc<dyn Array>, GovernanceError> {
        match policy {
            MaskingPolicy::Nullify => {
                // O(1) allocation-free null array creation
                Ok(new_null_array(&DataType::Utf8, array.len()))
            }
            MaskingPolicy::Hash => {
                let mut builder =
                    StringBuilder::with_capacity(array.len(), array.value_data().len());
                let mut hex_buffer = [0u8; 64]; // 256 bits = 32 bytes = 64 hex chars
                let hex_alphabet = b"0123456789abcdef";

                for i in 0..array.len() {
                    if array.is_null(i) {
                        builder.append_null();
                    } else {
                        let val = array.value(i);
                        let mut hasher = Sha256::new();
                        let salt = &crate::config::resolver::get_config().policy.hash_salt;
                        hasher.update(salt.as_bytes());
                        hasher.update(val.as_bytes());
                        let digest = hasher.finalize();

                        // Avoid hex::encode string allocation
                        for (i, &byte) in digest.iter().enumerate() {
                            hex_buffer[i * 2] = hex_alphabet[(byte >> 4) as usize];
                            hex_buffer[i * 2 + 1] = hex_alphabet[(byte & 0x0F) as usize];
                        }

                        // Unsafe is fine here because we control the alphabet
                        let hex_str = unsafe { std::str::from_utf8_unchecked(&hex_buffer) };
                        builder.append_value(hex_str);
                    }
                }
                Ok(std::sync::Arc::new(builder.finish()))
            }
            MaskingPolicy::DynamicString {
                prefix_len,
                mask_char,
                ref domain_suffix,
            } => {
                let mut builder =
                    StringBuilder::with_capacity(array.len(), array.value_data().len());

                // Pre-compute static portion to avoid allocating per-row
                let static_suffix = format!("{}{}", mask_char.to_string().repeat(3), domain_suffix);

                for i in 0..array.len() {
                    if array.is_null(i) {
                        builder.append_null();
                    } else {
                        let val = array.value(i);
                        let prefix = if val.len() >= prefix_len {
                            &val[..prefix_len]
                        } else {
                            val
                        };

                        // Push prefix and static suffix directly to builder without intermediate String allocation
                        builder.append_value(format!("{}{}", prefix, static_suffix));
                    }
                }
                Ok(std::sync::Arc::new(builder.finish()))
            }
        }
    }
}

pub fn parse_date_string_to_epoch_days(s: &str) -> Option<i32> {
    use chrono::{DateTime, NaiveDate};

    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
        return Some((nd - epoch).num_days() as i32);
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%d-%m-%Y") {
        let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
        return Some((nd - epoch).num_days() as i32);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
        return Some((dt.naive_utc().date() - epoch).num_days() as i32);
    }
    None
}

pub fn parse_date_string_to_timestamp_millis(s: &str) -> Option<i64> {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};

    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    // format dd-mm-yyyyThh:mm:ss:MMM
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%d-%m-%YT%H:%M:%S:%3f") {
        return Some(ndt.and_utc().timestamp_millis());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(
            nd.and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp_millis(),
        );
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%d-%m-%Y") {
        return Some(
            nd.and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp_millis(),
        );
    }

    None
}

fn build_scalar_string_array(
    s: &str,
    data_type: &arrow::datatypes::DataType,
    len: usize,
) -> Result<std::sync::Arc<dyn Array>, String> {
    use arrow::array::{
        Date32Array, Date64Array, TimestampMicrosecondArray, TimestampMillisecondArray,
        TimestampNanosecondArray, TimestampSecondArray,
    };
    use arrow::datatypes::{DataType, TimeUnit};

    if data_type == &DataType::Date32 {
        if let Some(days) = parse_date_string_to_epoch_days(s) {
            Ok(std::sync::Arc::new(Date32Array::from(vec![days; len])))
        } else {
            Err(format!("Could not parse '{}' as Date32", s))
        }
    } else if data_type == &DataType::Date64 {
        if let Some(millis) = parse_date_string_to_timestamp_millis(s) {
            Ok(std::sync::Arc::new(Date64Array::from(vec![millis; len])))
        } else {
            Err(format!("Could not parse '{}' as Date64", s))
        }
    } else if let DataType::Timestamp(tu, _) = data_type {
        if let Some(millis) = parse_date_string_to_timestamp_millis(s) {
            match tu {
                TimeUnit::Millisecond => Ok(std::sync::Arc::new(TimestampMillisecondArray::from(
                    vec![millis; len],
                ))),
                TimeUnit::Microsecond => Ok(std::sync::Arc::new(TimestampMicrosecondArray::from(
                    vec![millis * 1000; len],
                ))),
                TimeUnit::Nanosecond => Ok(std::sync::Arc::new(TimestampNanosecondArray::from(
                    vec![millis * 1_000_000; len],
                ))),
                TimeUnit::Second => Ok(std::sync::Arc::new(TimestampSecondArray::from(
                    vec![millis / 1000; len],
                ))),
            }
        } else {
            Err(format!("Could not parse '{}' as Timestamp", s))
        }
    } else {
        Ok(std::sync::Arc::new(StringArray::from(vec![s; len])))
    }
}
