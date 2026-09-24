mod common;
use common::MockPolicyProvider;
use holonomy_core::crypto::dek_cache::DekCache;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;
use arrow::record_batch::RecordBatch;
use holonomy_core::manager::scan_orchestrator::ScanOrchestrator;
use holonomy_core::ingestion::s3_client::{IngestionError, IngestionProvider};
use async_trait::async_trait;
use parquet::file::metadata::ParquetMetaData;
use bytes::Bytes;
use arrow::datatypes::{Schema, Field, DataType};
use parquet::arrow::arrow_writer::ArrowWriter;

use arrow::array::Int64Array;

// @trace TASK-124
#[derive(Clone)]
struct MockPrefetchS3Client {
    pub fetch_calls: Arc<AtomicUsize>,
    pub footer_delay_ms: u64,
}

impl MockPrefetchS3Client {
    pub fn new(footer_delay_ms: u64) -> Self {
        Self {
            fetch_calls: Arc::new(AtomicUsize::new(0)),
            footer_delay_ms,
        }
    }
    
    // helper to generate a valid parquet file
    fn generate_parquet() -> Vec<u8> {
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        let mut buf = Vec::new();
        {
            let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), None).unwrap();
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
            ).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
        }
        buf
    }
}

#[async_trait]
impl IngestionProvider for MockPrefetchS3Client {
    async fn fetch_byte_range(
        &self,
        _url: &str,
        range: std::ops::Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        println!("[{}] fetch_byte_range called for {} range {:?}", t, _url, range);
        // If we are fetching footer (e.g. range end > some threshold)
        if range.end > 0 {
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(self.footer_delay_ms)).await;
        }
        
        let buf = Self::generate_parquet();
        let end = std::cmp::min(range.end, buf.len());
        let start = std::cmp::min(range.start, end);
        let sliced = &buf[start..end];
        let bytes = Bytes::copy_from_slice(sliced);
        
        Ok(bytes)
    }

    async fn fetch_multiple_ranges(
        &self,
        _url: &str,
        ranges: Vec<std::ops::Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        let mut results = Vec::new();
        for range in ranges {
            results.push(self.fetch_byte_range(_url, range).await?);
        }
        Ok(results)
    }

    async fn fetch_parquet_metadata(
        &self,
        _url: &str,
        _decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<ParquetMetaData, IngestionError> {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        println!("[{}] fetch_parquet_metadata called for {}", t, _url);
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(self.footer_delay_ms)).await;
        
        let buf = Self::generate_parquet();
        let len = buf.len();
        let metadata_len = u32::from_le_bytes(buf[len - 8..len - 4].try_into().unwrap()) as usize;
        let metadata_bytes = &buf[len - 8 - metadata_len..len - 8];
        let metadata =
            parquet::file::metadata::ParquetMetaDataReader::decode_metadata(metadata_bytes)?;
        Ok(metadata)
    }

    async fn fetch_entire_file(&self, _url: &str) -> Result<Bytes, IngestionError> {
        Err(IngestionError::ParseFailed("Not found".to_string()))
    }
    
}

struct MockKmsProvider;

#[async_trait::async_trait]
impl holonomy_core::manager::crypto_manager::KmsProvider for MockKmsProvider {
    async fn decrypt_dek(
        &self,
        _wrapped_dek_ciphertext: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        Ok(b"1234567890123456".to_vec())
    }

    async fn wrap_key(
        &self,
        _key: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        Ok(b"kms_wrapped_mock".to_vec())
    }
}

#[tokio::test]
async fn test_concurrent_prefetch() {
    let mock_s3 = Arc::new(MockPrefetchS3Client::new(500));
    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(100));
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(holonomy_core::manager::crypto_manager::CryptoManager::new(
        dek_cache, Arc::new(MockKmsProvider)
    ));
    let policy_manager = Arc::new(holonomy_core::manager::policy_manager::PolicyManager::new_dangerously_allow_unsigned(Arc::new(MockPolicyProvider)));
    let gov_manager = Arc::new(holonomy_core::manager::governance_manager::GovernanceManager::new(Arc::new(common::MockSchemaRegistryProvider)));
    
    let orchestrator = ScanOrchestrator::new(
        audit_buffer,
        mock_s3.clone(),
        crypto_manager,
        policy_manager,
        gov_manager,
    );
    
    let user_ctx = holonomy_core::auth::jwt_validator::UserContext {
        sub: Some("user".to_string()),
        client_id: None,
        email: None,
        principals: vec!["role1".into()],
        extra: std::collections::HashMap::new(),
    };
    
    let targets = vec![
        "mock://file1.parquet".to_string(),
        "mock://file2.parquet".to_string(),
        "mock://file3.parquet".to_string(),
    ];
    
    let start_time = std::time::Instant::now();
    let scan_iter = orchestrator.scan(
        targets,
        Some("test"),
        &user_ctx,
        None,
        &[],
        None,
        None,
        None,
        None,
    ).await.expect("Failed to create scan iterator");
    
    // We haven't awaited the first batch yet, but the background task is spawned.
    // Let's yield and wait briefly to let background tasks fetch footers.
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Since buffered(2) is used, we expect 2 footer fetches to be in-flight concurrently.
    // wait for them to finish (takes 500ms).
    // Let's just collect all batches.
    
    let batch_count = tokio::task::spawn_blocking(move || {
        let mut count = 0;
        for batch in scan_iter {
            batch.unwrap();
            count += 1;
        }
        count
    }).await.unwrap();
    
    assert_eq!(batch_count, 3);
    
    let duration = start_time.elapsed();
    // 3 files, each footer takes 500ms. If sequential, it would take 1500ms.
    // With concurrent fetching:
    // 500ms initial metadata
    // 500ms file1 async metadata (file2 async metadata concurrent)
    // 500ms file1 data (file3 async metadata concurrent)
    // 500ms file2 data
    // 500ms file3 data
    // Total should be around 2500ms.
    
    assert!(
        duration.as_millis() < 2800,
        "Execution took too long, prefetching is not concurrent"
    );
}
