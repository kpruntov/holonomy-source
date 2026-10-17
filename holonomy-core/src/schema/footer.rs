// @trace TASK-044
// @trace TASK-072
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use parquet::file::metadata::ParquetMetaData;
use parquet::file::metadata::ParquetMetaDataReader;
use reqwest::{Client as ReqwestClient, header::RANGE};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FooterError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("S3 error: {0}")]
    S3Error(String),
    #[error("Byte stream error")]
    ByteStreamError,
    #[error("Invalid Parquet file: {0}")]
    InvalidParquet(String),
    #[error("Parquet Parse Error: {0}")]
    ParseError(#[from] parquet::errors::ParquetError),
    #[error("Unsupported URI: {0}")]
    UnsupportedUri(String),
}

pub async fn fetch_parquet_metadata(
    s3_client: Option<&S3Client>,
    reqwest_client: Option<&ReqwestClient>,
    uri: &str,
) -> Result<ParquetMetaData, FooterError> {
    let (is_aws, is_http, bucket, key, http_uri) =
        if uri.starts_with("http://") || uri.starts_with("https://") {
            (false, true, String::new(), String::new(), uri.to_string())
        } else if let Some(path) = uri.strip_prefix("s3://") {
            if let Some((b, k)) = path.split_once('/') {
                (true, false, b.to_string(), k.to_string(), String::new())
            } else {
                return Err(FooterError::UnsupportedUri("Invalid s3 URI".into()));
            }
        } else if let Some(path) = uri.strip_prefix("r2://") {
            if let Some((b, k)) = path.split_once('/') {
                (true, false, b.to_string(), k.to_string(), String::new())
            } else {
                return Err(FooterError::UnsupportedUri("Invalid r2 URI".into()));
            }
        } else {
            (false, false, String::new(), String::new(), uri.to_string())
        };

    if is_aws {
        let s3 = s3_client.ok_or_else(|| {
            FooterError::UnsupportedUri("S3 client required for s3/r2 URIs".into())
        })?;

        let resp = s3
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .range("bytes=-8")
            .send()
            .await
            .map_err(|e| FooterError::S3Error(format!("{:?}", e)))?;

        let footer_bytes = resp
            .body
            .collect()
            .await
            .map_err(|_| FooterError::ByteStreamError)?
            .into_bytes();
        if footer_bytes.len() < 8 {
            return Err(FooterError::InvalidParquet("File too small".into()));
        }

        let magic = &footer_bytes[4..8];
        if magic != b"PAR1" && magic != b"PARE" {
            return Err(FooterError::InvalidParquet("Invalid magic number".into()));
        }

        let metadata_len = u32::from_le_bytes(footer_bytes[0..4].try_into().unwrap()) as usize;
        let fetch_len = metadata_len + 8;

        let resp = s3
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .range(format!("bytes=-{}", fetch_len))
            .send()
            .await
            .map_err(|e| FooterError::S3Error(e.to_string()))?;

        let full_footer = resp
            .body
            .collect()
            .await
            .map_err(|_| FooterError::ByteStreamError)?
            .into_bytes();

        let metadata = ParquetMetaDataReader::new().parse_and_finish(&full_footer)?;
        Ok(metadata)
    } else if is_http {
        let reqwest = reqwest_client.ok_or_else(|| {
            FooterError::UnsupportedUri("Reqwest client required for http/https URIs".into())
        })?;

        let resp = reqwest
            .get(&http_uri)
            .header(RANGE, "bytes=-8")
            .send()
            .await?
            .error_for_status()?;

        let footer_bytes = resp.bytes().await?;
        if footer_bytes.len() < 8 {
            return Err(FooterError::InvalidParquet("File too small".into()));
        }

        let magic = &footer_bytes[4..8];
        if magic != b"PAR1" && magic != b"PARE" {
            return Err(FooterError::InvalidParquet("Invalid magic number".into()));
        }

        let metadata_len = u32::from_le_bytes(footer_bytes[0..4].try_into().unwrap()) as usize;
        let fetch_len = metadata_len + 8;

        let resp = reqwest
            .get(&http_uri)
            .header(RANGE, format!("bytes=-{}", fetch_len))
            .send()
            .await?
            .error_for_status()?;

        let full_footer = resp.bytes().await?;

        let metadata = ParquetMetaDataReader::new().parse_and_finish(&full_footer)?;
        Ok(metadata)
    } else {
        // Local file logic
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mut file =
            File::open(&http_uri).map_err(|e| FooterError::InvalidParquet(e.to_string()))?;
        let len = file
            .metadata()
            .map_err(|e| FooterError::InvalidParquet(e.to_string()))?
            .len();
        if len < 8 {
            return Err(FooterError::InvalidParquet("File too small".into()));
        }

        file.seek(SeekFrom::End(-8))
            .map_err(|e| FooterError::InvalidParquet(e.to_string()))?;
        let mut footer_bytes = [0u8; 8];
        file.read_exact(&mut footer_bytes)
            .map_err(|e| FooterError::InvalidParquet(e.to_string()))?;

        let magic = &footer_bytes[4..8];
        if magic != b"PAR1" && magic != b"PARE" {
            return Err(FooterError::InvalidParquet("Invalid magic number".into()));
        }

        let metadata_len = u32::from_le_bytes(footer_bytes[0..4].try_into().unwrap()) as usize;
        let fetch_len = metadata_len + 8;

        file.seek(SeekFrom::End(-(fetch_len as i64)))
            .map_err(|e| FooterError::InvalidParquet(e.to_string()))?;
        let mut full_footer = vec![0u8; fetch_len];
        file.read_exact(&mut full_footer)
            .map_err(|e| FooterError::InvalidParquet(e.to_string()))?;

        let metadata = ParquetMetaDataReader::new().parse_and_finish(&Bytes::from(full_footer))?;
        Ok(metadata)
    }
}
