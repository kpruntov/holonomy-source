// @trace TASK-010
// @trace TASK-123
// @trace TASK-040
// @trace TASK-042
// @trace TASK-089
// @trace TASK-090
// @trace TASK-091
// @trace TASK-092
// @trace LCOMP-001
// @trace ADR-011
use aws_credential_types::provider::ProvideCredentials;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use parquet::errors::ParquetError;
use parquet::file::metadata::ParquetMetaDataReader;
use reqwest::{Client, Error as ReqwestError, header};
use std::ops::Range;
use std::time::Duration;

#[async_trait::async_trait]
pub trait IngestionProvider: Send + Sync {
    async fn fetch_byte_range(
        &self,
        url: &str,
        range: Range<usize>,
    ) -> Result<Bytes, IngestionError>;

    async fn fetch_entire_file(&self, url: &str) -> Result<Bytes, IngestionError>;

    async fn fetch_multiple_ranges(
        &self,
        url: &str,
        ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError>;

    async fn fetch_parquet_metadata(
        &self,
        url: &str,
        decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, IngestionError>;
}

/// S3/HTTP client for targeted byte-range requests.
pub struct S3Client {
    client: Client,
    pub sdk_config: Option<aws_config::SdkConfig>,
}

#[derive(Debug)]
pub enum IngestionError {
    Http(ReqwestError),
    Parquet(ParquetError),
    InvalidFooter,
    ContentLengthMissing,
    ParseFailed(String),
}

impl From<ReqwestError> for IngestionError {
    fn from(err: ReqwestError) -> Self {
        IngestionError::Http(err)
    }
}

impl From<ParquetError> for IngestionError {
    fn from(err: ParquetError) -> Self {
        IngestionError::Parquet(err)
    }
}

#[derive(Debug, Clone)]
pub struct ParsedS3Url {
    pub bucket: String,
    pub key: String,
    pub http_url: String,
    pub region: String,
}

impl Default for S3Client {
    fn default() -> Self {
        Self::new(None)
    }
}

impl S3Client {
    pub fn new(sdk_config: Option<aws_config::SdkConfig>) -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(100)
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { client, sdk_config }
    }

    pub fn parse_url(&self, url: &str) -> Result<ParsedS3Url, IngestionError> {
        let region = self.sdk_config
            .as_ref()
            .and_then(|c| c.region().map(|r| r.as_ref().to_string()))
            .unwrap_or_else(|| "us-east-1".to_string());

        let endpoint_url = self.sdk_config
            .as_ref()
            .and_then(|c| c.endpoint_url().map(|s| s.to_string()))
            .or_else(|| {
                std::env::var("AWS_ENDPOINT_URL_S3")
                    .or_else(|_| std::env::var("AWS_ENDPOINT_URL"))
                    .ok()
            });

        let (bucket, key) = if url.starts_with("s3://") || url.starts_with("r2://") {
            let without_scheme = url
                .strip_prefix("s3://")
                .or_else(|| url.strip_prefix("r2://"))
                .unwrap_or(url);

            let slash_idx = without_scheme.find('/').ok_or_else(|| {
                IngestionError::ParseFailed("Missing key in S3/R2 URL".to_string())
            })?;

            let bucket = &without_scheme[..slash_idx];
            let key = &without_scheme[slash_idx + 1..];
            (bucket.to_string(), key.to_string())
        } else if url.starts_with("http://") || url.starts_with("https://") {
            let without_scheme = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("https://"))
                .unwrap_or(url);

            let slash_idx = without_scheme.find('/').unwrap_or(without_scheme.len());
            let domain = &without_scheme[..slash_idx];
            let path = if slash_idx < without_scheme.len() {
                &without_scheme[slash_idx + 1..]
            } else {
                ""
            };

            if domain.contains(".s3.") {
                let bucket = domain.split('.').next().unwrap_or("").to_string();
                (bucket, path.to_string())
            } else {
                let bucket_slash = path.find('/').unwrap_or(path.len());
                let bucket = &path[..bucket_slash];
                let key = if bucket_slash < path.len() {
                    &path[bucket_slash + 1..]
                } else {
                    ""
                };
                (bucket.to_string(), key.to_string())
            }
        } else {
            return Err(IngestionError::ParseFailed(
                "Unsupported URL scheme".to_string(),
            ));
        };

        let http_url = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else if let Some(ep) = endpoint_url {
            let ep = ep.trim_end_matches('/');
            format!("{}/{}/{}", ep, bucket, key)
        } else if url.starts_with("r2://") {
            let account_id =
                std::env::var("CF_ACCOUNT_ID").unwrap_or_else(|_| "unknown_account".to_string());
            format!(
                "https://{}.r2.cloudflarestorage.com/{}/{}",
                account_id, bucket, key
            )
        } else {
            format!("https://{}.s3.{}.amazonaws.com/{}", bucket, region, key)
        };

        Ok(ParsedS3Url {
            bucket,
            key,
            http_url,
            region,
        })
    }

    pub async fn sign_request(
        &self,
        request: &mut reqwest::Request,
        region: &str,
    ) -> Result<(), IngestionError> {
        let sdk_config = match &self.sdk_config {
            Some(c) => c,
            None => return Ok(()),
        };

        let credentials_provider = match sdk_config.credentials_provider() {
            Some(provider) => provider,
            None => return Ok(()),
        };

        let credentials = credentials_provider
            .provide_credentials()
            .await
            .map_err(|e| IngestionError::ParseFailed(format!("Creds error: {}", e)))?;

        if !request.headers().contains_key("x-amz-content-sha256") {
            request.headers_mut().insert(
                reqwest::header::HeaderName::from_static("x-amz-content-sha256"),
                reqwest::header::HeaderValue::from_static(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
            );
        }

        // reqwest does not inject the Host header until the transport layer,
        // but AWS SigV4 strictly requires it in the Canonical Request.
        if !request.headers().contains_key(reqwest::header::HOST)
            && let Some(host) = request.url().host_str()
        {
            let host_header = if let Some(port) = request.url().port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            request.headers_mut().insert(
                reqwest::header::HOST,
                reqwest::header::HeaderValue::from_str(&host_header).unwrap(),
            );
        }

        let url_str = request.url().as_str();
        let method = request.method().as_str();

        let mut headers_vec = Vec::new();
        for (k, v) in request.headers().iter() {
            if let Ok(v_str) = v.to_str() {
                headers_vec.push((k.as_str(), v_str));
            }
        }

        let signable_request = aws_sigv4::http_request::SignableRequest::new(
            method,
            url_str,
            headers_vec.into_iter(),
            aws_sigv4::http_request::SignableBody::Bytes(&[]),
        )
        .map_err(|e| IngestionError::ParseFailed(format!("SignableRequest error: {}", e)))?;

        let signing_settings = aws_sigv4::http_request::SigningSettings::default();
        let identity =
            aws_smithy_runtime_api::client::identity::Identity::new(credentials.clone(), None);
        let builder = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name("s3")
            .time(std::time::SystemTime::now())
            .settings(signing_settings);

        let signing_params = builder
            .build()
            .map_err(|e| IngestionError::ParseFailed(format!("SigningParams error: {}", e)))?;

        let (signing_instructions, _signature) =
            aws_sigv4::http_request::sign(signable_request, &signing_params.into())
                .map_err(|e| IngestionError::ParseFailed(format!("Signing error: {:?}", e)))?
                .into_parts();

        for (k, v) in signing_instructions.headers() {
            if let (Ok(k_name), Ok(v_val)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                request.headers_mut().insert(k_name, v_val);
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl IngestionProvider for S3Client {
    /// Fetches a specific byte range from the given URL.
    async fn fetch_byte_range(
        &self,
        url: &str,
        range: Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        let parsed = self.parse_url(url)?;
        let range_header = format!("bytes={}-{}", range.start, range.end - 1);
        let mut request = self
            .client
            .get(&parsed.http_url)
            .header(header::RANGE, range_header)
            .build()?;

        self.sign_request(&mut request, &parsed.region).await?;

        let response = self.client.execute(request).await?.error_for_status()?;

        Ok(response.bytes().await?)
    }

    async fn fetch_entire_file(&self, url: &str) -> Result<Bytes, IngestionError> {
        let parsed = self.parse_url(url)?;
        let mut request = self
            .client
            .get(&parsed.http_url)
            .build()?;
        self.sign_request(&mut request, &parsed.region).await?;
        let response = self.client.execute(request).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(IngestionError::ParseFailed("ObjectNotFound".into()));
        }
        let response = response.error_for_status()?;
        Ok(response.bytes().await?)
    }

    /// Orchestrates fetching multiple byte ranges in parallel to saturate network
    /// using bounded concurrency to prevent TCP port exhaustion.
    async fn fetch_multiple_ranges(
        &self,
        url: &str,
        ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        let futures = ranges
            .into_iter()
            .map(|range| self.fetch_byte_range(url, range));

        let mut results: Vec<Result<Bytes, IngestionError>> = stream::iter(futures)
            .buffered(100) // Bound concurrency to 100 max in-flight requests
            .collect()
            .await;

        let mut final_results = Vec::with_capacity(results.len());
        for res in results.drain(..) {
            final_results.push(res?);
        }
        Ok(final_results)
    }

    /// Fetches and parses the Parquet footer using a speculative read to minimize RTT latency.
    async fn fetch_parquet_metadata(
        &self,
        url: &str,
        decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, IngestionError> {
        // 1. Speculative read of the last 64KB (typical max parquet footer size)
        let parsed = self.parse_url(url)?;
        let fetch_size = 65536;
        let range_header = format!("bytes=-{}", fetch_size);

        let mut request = self
            .client
            .get(&parsed.http_url)
            .header(header::RANGE, range_header)
            .build()?;

        self.sign_request(&mut request, &parsed.region).await?;

        let response = self.client.execute(request).await?.error_for_status()?;

        let buf = response.bytes().await?;
        let buf_len = buf.len();

        if buf_len < 8 {
            return Err(IngestionError::InvalidFooter);
        }

        if &buf[buf_len - 4..buf_len] != b"PAR1" {
            return Err(IngestionError::InvalidFooter);
        }

        let metadata_len =
            u32::from_le_bytes(buf[buf_len - 8..buf_len - 4].try_into().unwrap()) as usize;

        if metadata_len + 8 <= buf_len {
            // Fast path: Metadata is entirely within our speculative buffer
            let metadata_with_footer = &buf[buf_len - 8 - metadata_len..buf_len];
            let reader = bytes::Bytes::copy_from_slice(metadata_with_footer);
            let mut builder = ParquetMetaDataReader::new();
            if let Some(props) = decryption_props.clone() {
                builder = builder.with_decryption_properties(Some(std::sync::Arc::new(props)));
            }
            return Ok(builder.parse_and_finish(&reader)?);
        }

        // Slow path: Metadata is larger than 64KB
        // We fallback to checking exactly what the content length is and making an exact range request.
        let mut head_req = self.client.head(&parsed.http_url).build()?;
        self.sign_request(&mut head_req, &parsed.region).await?;
        let head_resp = self.client.execute(head_req).await?.error_for_status()?;
        let content_length = head_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or(IngestionError::ContentLengthMissing)?;

        if content_length < metadata_len + 8 {
            return Err(IngestionError::InvalidFooter);
        }

        let metadata_range = (content_length - 8 - metadata_len)..content_length;
        let exact_metadata_bytes = self.fetch_byte_range(url, metadata_range).await?;

        let reader = exact_metadata_bytes;
        let mut builder = ParquetMetaDataReader::new();
        if let Some(props) = decryption_props {
            builder = builder.with_decryption_properties(Some(std::sync::Arc::new(props)));
        }
        Ok(builder.parse_and_finish(&reader)?)
    }
}

use parquet::file::statistics::Statistics;

use serde::{Deserialize, Serialize};

// @trace TASK-053
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PredicateValue {
    Int64(i64),
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Predicate {
    Eq {
        column: String,
        value: PredicateValue,
    },
    Neq {
        column: String,
        value: PredicateValue,
    },
    Gt {
        column: String,
        value: PredicateValue,
    },
    Lt {
        column: String,
        value: PredicateValue,
    },
}

impl Predicate {
    pub fn parse_filter(filter_str: &str) -> Option<Self> {
        let operators = ["==", "!=", "=", ">", "<"];
        for op in operators {
            if let Some(idx) = filter_str.find(op) {
                let col = filter_str[..idx].trim().to_string();
                let val_str = filter_str[idx + op.len()..].trim();
                let val = if val_str.starts_with('\'') && val_str.ends_with('\'') {
                    PredicateValue::String(val_str[1..val_str.len() - 1].to_string())
                } else if let Ok(num) = val_str.parse::<i64>() {
                    PredicateValue::Int64(num)
                } else {
                    PredicateValue::String(val_str.to_string())
                };

                return match op {
                    "==" | "=" => Some(Predicate::Eq {
                        column: col,
                        value: val,
                    }),
                    "!=" => Some(Predicate::Neq {
                        column: col,
                        value: val,
                    }),
                    ">" => Some(Predicate::Gt {
                        column: col,
                        value: val,
                    }),
                    "<" => Some(Predicate::Lt {
                        column: col,
                        value: val,
                    }),
                    _ => None,
                };
            }
        }
        None
    }

    pub fn column(&self) -> &str {
        match self {
            Predicate::Eq { column, .. } => column,
            Predicate::Neq { column, .. } => column,
            Predicate::Gt { column, .. } => column,
            Predicate::Lt { column, .. } => column,
        }
    }

    pub fn evaluate_statistics(&self, stats: &Statistics) -> bool {
        match (self, stats) {
            (Predicate::Neq { .. }, _) => true, // Conservatively keep row group for Neq
            (
                Predicate::Eq {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int64(s),
            ) => {
                if let (Some(min), Some(max)) = (s.min_opt(), s.max_opt()) {
                    *v >= *min && *v <= *max
                } else {
                    true
                }
            }
            (
                Predicate::Eq {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int32(s),
            ) => {
                if let (Some(min), Some(max)) = (s.min_opt(), s.max_opt()) {
                    *v >= (*min as i64) && *v <= (*max as i64)
                } else {
                    true
                }
            }
            (
                Predicate::Gt {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int64(s),
            ) => {
                if let Some(max) = s.max_opt() {
                    *max > *v
                } else {
                    true
                }
            }
            (
                Predicate::Gt {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int32(s),
            ) => {
                if let Some(max) = s.max_opt() {
                    (*max as i64) > *v
                } else {
                    true
                }
            }
            (
                Predicate::Lt {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int64(s),
            ) => {
                if let Some(min) = s.min_opt() {
                    *min < *v
                } else {
                    true
                }
            }
            (
                Predicate::Lt {
                    value: PredicateValue::Int64(v),
                    ..
                },
                Statistics::Int32(s),
            ) => {
                if let Some(min) = s.min_opt() {
                    (*min as i64) < *v
                } else {
                    true
                }
            }
            (
                Predicate::Eq {
                    value: PredicateValue::String(v),
                    ..
                },
                _,
            ) => {
                if let (Some(min_bytes), Some(max_bytes)) =
                    (stats.min_bytes_opt(), stats.max_bytes_opt())
                {
                    let v_bytes = v.as_bytes();
                    v_bytes >= min_bytes && v_bytes <= max_bytes
                } else {
                    true
                }
            }
            // If statistics are missing or type mismatch, we must not prune to avoid dropping valid data
            _ => true,
        }
    }
}

impl S3Client {
    /// Extracts byte ranges for all chunks of a specific column from the metadata.
    pub fn get_column_byte_ranges(
        metadata: &parquet::file::metadata::ParquetMetaData,
        column_name: &str,
    ) -> Vec<Range<usize>> {
        Self::get_pruned_column_byte_ranges(metadata, column_name, &[])
    }

    // @trace TASK-054
    /// Extracts byte ranges for multiple projected columns.
    pub fn get_projected_column_byte_ranges(
        metadata: &parquet::file::metadata::ParquetMetaData,
        column_names: &[&str],
        predicates: &[Predicate],
    ) -> std::collections::HashMap<String, Vec<Range<usize>>> {
        let mut result = std::collections::HashMap::new();
        for &col in column_names {
            let ranges = Self::get_pruned_column_byte_ranges(metadata, col, predicates);
            result.insert(col.to_string(), ranges);
        }
        result
    }

    /// Evaluates predicates against Parquet row group stats to prune blocks before I/O (LF-033).
    pub fn get_pruned_column_byte_ranges(
        metadata: &parquet::file::metadata::ParquetMetaData,
        column_name: &str,
        predicates: &[Predicate],
    ) -> Vec<Range<usize>> {
        let mut ranges = Vec::new();

        let file_metadata = metadata.file_metadata();
        let schema = file_metadata.schema();
        let col_idx = schema
            .get_fields()
            .iter()
            .position(|c| c.name() == column_name);

        if let Some(idx) = col_idx {
            for row_group in metadata.row_groups() {
                let mut keep = true;
                for predicate in predicates {
                    let pred_col_idx = schema.get_fields().iter().position(|c| {
                        c.name()
                            == match predicate {
                                Predicate::Eq { column, .. } => column,
                                Predicate::Neq { column, .. } => column,
                                Predicate::Gt { column, .. } => column,
                                Predicate::Lt { column, .. } => column,
                            }
                    });

                    if let Some(p_idx) = pred_col_idx
                        && let Some(col_chunk) = row_group.columns().get(p_idx)
                        && let Some(stats) = col_chunk.statistics()
                        && !predicate.evaluate_statistics(stats)
                    {
                        keep = false;
                        break;
                    }
                }

                if keep && let Some(col_chunk) = row_group.columns().get(idx) {
                    let (start, len) = col_chunk.byte_range();
                    ranges.push((start as usize)..(start as usize + len as usize));
                }
            }
        }

        ranges
    }

    /// Evaluates predicates against Parquet row group stats to return valid row group indices.
    pub fn get_pruned_row_groups(
        metadata: &parquet::file::metadata::ParquetMetaData,
        column_name: &str,
        predicates: &[Predicate],
    ) -> Vec<usize> {
        let mut row_groups = Vec::new();

        let file_metadata = metadata.file_metadata();
        let schema = file_metadata.schema();
        let col_idx = schema
            .get_fields()
            .iter()
            .position(|c| c.name() == column_name);

        if col_idx.is_some() {
            for (i, row_group) in metadata.row_groups().iter().enumerate() {
                let mut keep = true;
                for predicate in predicates {
                    let pred_col_idx = schema.get_fields().iter().position(|c| {
                        c.name()
                            == match predicate {
                                Predicate::Eq { column, .. } => column,
                                Predicate::Neq { column, .. } => column,
                                Predicate::Gt { column, .. } => column,
                                Predicate::Lt { column, .. } => column,
                            }
                    });

                    if let Some(p_idx) = pred_col_idx
                        && let Some(col_chunk) = row_group.columns().get(p_idx)
                        && let Some(stats) = col_chunk.statistics()
                        && !predicate.evaluate_statistics(stats)
                    {
                        keep = false;
                        break;
                    }
                }

                if keep {
                    row_groups.push(i);
                }
            }
        }

        row_groups
    }
}

// @trace TASK-059
pub struct S3AsyncFileReader {
    client: std::sync::Arc<dyn IngestionProvider>,
    url: String,
    decryption_props:
        Option<std::sync::Arc<parquet::encryption::decrypt::FileDecryptionProperties>>,
}

impl S3AsyncFileReader {
    pub fn new(
        client: std::sync::Arc<dyn IngestionProvider>,
        url: String,
        decryption_props: Option<
            std::sync::Arc<parquet::encryption::decrypt::FileDecryptionProperties>,
        >,
    ) -> Self {
        Self {
            client,
            url,
            decryption_props,
        }
    }
}

impl parquet::arrow::async_reader::AsyncFileReader for S3AsyncFileReader {
    fn get_bytes(
        &mut self,
        range: std::ops::Range<u64>,
    ) -> futures::future::BoxFuture<'_, parquet::errors::Result<bytes::Bytes>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let range_usize = range.start as usize..range.end as usize;
        Box::pin(async move {
            client
                .fetch_byte_range(&url, range_usize)
                .await
                .map_err(|e| parquet::errors::ParquetError::General(format!("{:?}", e)))
        })
    }

    fn get_byte_ranges(
        &mut self,
        ranges: Vec<std::ops::Range<u64>>,
    ) -> futures::future::BoxFuture<'_, parquet::errors::Result<Vec<bytes::Bytes>>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let ranges_usize: Vec<std::ops::Range<usize>> = ranges
            .into_iter()
            .map(|r| r.start as usize..r.end as usize)
            .collect();
        Box::pin(async move {
            client
                .fetch_multiple_ranges(&url, ranges_usize)
                .await
                .map_err(|e| parquet::errors::ParquetError::General(format!("{:?}", e)))
        })
    }

    fn get_metadata(
        &mut self,
        _options: std::option::Option<&parquet::arrow::arrow_reader::ArrowReaderOptions>,
    ) -> futures::future::BoxFuture<
        '_,
        parquet::errors::Result<std::sync::Arc<parquet::file::metadata::ParquetMetaData>>,
    > {
        let client = self.client.clone();
        let url = self.url.clone();
        let dec_props = self.decryption_props.as_ref().map(|arc| (**arc).clone());
        Box::pin(async move {
            client
                .fetch_parquet_metadata(&url, dec_props)
                .await
                .map(std::sync::Arc::new)
                .map_err(|e| parquet::errors::ParquetError::General(format!("{:?}", e)))
        })
    }
}
