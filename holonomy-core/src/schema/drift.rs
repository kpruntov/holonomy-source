// @trace TASK-046
use crate::schema::footer::{FooterError, fetch_parquet_metadata};
use parquet::schema::types::SchemaDescriptor;
use reqwest::Client;
use std::fs;
use std::path::Path;

pub fn has_schema_drift(base: &SchemaDescriptor, sample: &SchemaDescriptor) -> bool {
    if base.columns().len() != sample.columns().len() {
        return true;
    }

    for (base_col, col) in base.columns().iter().zip(sample.columns().iter()) {
        if base_col.name() != col.name()
            || base_col.physical_type() != col.physical_type()
            || base_col.logical_type_ref() != col.logical_type_ref()
        {
            return true;
        }
    }

    false
}

pub async fn check_local_directory_drift(dir_path: &str) -> Result<bool, FooterError> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        return Ok(false);
    }

    let entries = fs::read_dir(path).map_err(|e| FooterError::InvalidParquet(e.to_string()))?;

    let mut parquet_files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| FooterError::InvalidParquet(e.to_string()))?;
        let file_path = entry.path();
        if file_path.is_file() && file_path.extension().and_then(|s| s.to_str()) == Some("parquet")
        {
            parquet_files.push(file_path.to_string_lossy().to_string());
            if parquet_files.len() >= 51 {
                break;
            }
        }
    }

    if parquet_files.is_empty() {
        return Ok(false);
    }

    parquet_files.sort();

    let drift_detected = check_drift_for_uris(&parquet_files).await?;

    if drift_detected {
        eprintln!(
            "WARNING: Structural mutations (schema drift) detected within directory {}",
            dir_path
        );
    }

    Ok(drift_detected)
}

pub async fn check_drift_for_uris(uris: &[String]) -> Result<bool, FooterError> {
    if uris.is_empty() {
        return Ok(false);
    }

    let client = Client::new();
    let config = crate::config::resolver::get_config();
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if !config.storage.endpoint.is_empty() {
        loader = loader.endpoint_url(&config.storage.endpoint);
    }
    if !config.storage.region.is_empty() {
        loader = loader.region(aws_config::Region::new(config.storage.region.clone()));
    }
    let aws_config = loader.load().await;
    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .force_path_style(true)
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(s3_config);

    let base_metadata =
        match fetch_parquet_metadata(Some(&s3_client), Some(&client), &uris[0]).await {
            Ok(m) => m,
            Err(_) => return Ok(false),
        };

    let base_schema = base_metadata.file_metadata().schema_descr();
    let mut drift_detected = false;

    for uri in uris.iter().skip(1) {
        let metadata = match fetch_parquet_metadata(Some(&s3_client), Some(&client), uri).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        let schema = metadata.file_metadata().schema_descr();

        if has_schema_drift(base_schema, schema) {
            drift_detected = true;
            break;
        }
    }

    Ok(drift_detected)
}

pub fn get_first_parquet_file(dir_path: &str) -> Option<String> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        return None;
    }

    if let Ok(mut entries) = fs::read_dir(path) {
        let mut files = Vec::new();
        while let Some(Ok(entry)) = entries.next() {
            let file_path = entry.path();
            if file_path.is_file()
                && file_path.extension().and_then(|s| s.to_str()) == Some("parquet")
            {
                files.push(file_path.to_string_lossy().to_string());
            }
        }
        files.sort();
        if !files.is_empty() {
            return Some(files[0].clone());
        }
    }
    None
}
