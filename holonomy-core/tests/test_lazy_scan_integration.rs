// @trace TASK-065, TASK-066
mod common;
use common::MockPolicyProvider;
// @trace TASK-055
use bytes::Bytes;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::ingestion::s3_client::{IngestionError, IngestionProvider};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::policy_manager::PolicyManager;
use holonomy_core::manager::read_orchestrator::ReadOrchestrator;
use holonomy_core::manager::scan_orchestrator::ScanOrchestrator;
use std::fs;
use std::ops::Range;
use std::sync::Arc;

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

struct MockIngestionProvider {
    parquet_data: Vec<u8>,
}

#[async_trait::async_trait]
impl IngestionProvider for MockIngestionProvider {
    async fn fetch_byte_range(
        &self,
        _url: &str,
        range: Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        if range.end > self.parquet_data.len() {
            return Err(IngestionError::ParseFailed(
                "Range out of bounds".to_string(),
            ));
        }
        Ok(Bytes::copy_from_slice(&self.parquet_data[range]))
    }

    async fn fetch_multiple_ranges(
        &self,
        _url: &str,
        ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        let mut results = Vec::new();
        for range in ranges {
            if range.end > self.parquet_data.len() {
                return Err(IngestionError::ParseFailed(
                    "Range out of bounds".to_string(),
                ));
            }
            results.push(Bytes::copy_from_slice(&self.parquet_data[range]));
        }
        Ok(results)
    }

    async fn fetch_parquet_metadata(
        &self,
        _url: &str,
        _decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, IngestionError> {
        let len = self.parquet_data.len();
        if len < 8 {
            return Err(IngestionError::InvalidFooter);
        }
        let metadata_len =
            u32::from_le_bytes(self.parquet_data[len - 8..len - 4].try_into().unwrap()) as usize;
        let metadata_bytes = &self.parquet_data[len - 8 - metadata_len..len - 8];
        let metadata =
            parquet::file::metadata::ParquetMetaDataReader::decode_metadata(metadata_bytes)?;
        Ok(metadata)
    }

    async fn fetch_entire_file(&self, _url: &str) -> Result<Bytes, IngestionError> {
        Err(IngestionError::ParseFailed("Not found".to_string()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scan_and_read_identical() {
    let parquet_data = fs::read("tests/sample.parquet").expect("Failed to read sample.parquet");

    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let s3_client = Arc::new(MockIngestionProvider { parquet_data });
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(dek_cache, Arc::new(MockKmsProvider)));
    let policy_manager = Arc::new(PolicyManager::new_dangerously_allow_unsigned(
        std::sync::Arc::new(MockPolicyProvider),
    ));
    let governance_manager = Arc::new(GovernanceManager::new(std::sync::Arc::new(
        common::MockSchemaRegistryProvider,
    )));

    let read_orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        s3_client.clone(),
        crypto_manager.clone(),
        policy_manager.clone(),
        governance_manager.clone(),
    );

    let scan_orchestrator = ScanOrchestrator::new(
        audit_buffer.clone(),
        s3_client.clone(),
        crypto_manager.clone(),
        policy_manager.clone(),
        governance_manager.clone(),
    );

    let read_array = read_orchestrator
        .read(
            "mock://sample.parquet",
            Some("purpose"),
            &holonomy_core::auth::jwt_validator::UserContext {
                sub: Some("mock_user_hash".to_string()),
                client_id: None,
                email: None,
                principals: vec![],
                extra: std::collections::HashMap::new(),
            },
            "id",
            None,
            None,
            None,
        )
        .await
        .expect("Read failed");

    let scan_reader = scan_orchestrator
        .scan(
            vec!["mock://sample.parquet".to_string()],
            Some("purpose"),
            &holonomy_core::auth::jwt_validator::UserContext {
                sub: Some("mock_user_hash".to_string()),
                client_id: None,
                email: None,
                principals: vec![],
                extra: std::collections::HashMap::new(),
            },
            Some(vec!["id".to_string()]),
            &[],
            None,
            None,
            None,
            None,
        )
        .await
        .expect("Scan failed");

    let scan_arrays = tokio::task::spawn_blocking(move || {
        let mut arrays = Vec::new();
        for batch_res in scan_reader {
            let batch = batch_res.expect("Expected valid batch");
            assert_eq!(batch.num_columns(), 1);
            arrays.push(batch.column(0).clone());
        }
        arrays
    })
    .await
    .unwrap();

    use arrow::array::{Array, Int64Array};

    let refs: Vec<&dyn Array> = scan_arrays.iter().map(|a| a.as_ref()).collect();
    let scan_array = arrow::compute::concat(&refs).unwrap();

    let read_int = read_array
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Expected Int64Array from read_orchestrator");
    let scan_int = scan_array
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Expected Int64Array from scan_orchestrator");

    assert_eq!(
        read_int.len(),
        scan_int.len(),
        "Total row counts must match"
    );
    for i in 0..read_int.len() {
        assert_eq!(read_int.value(i), scan_int.value(i));
    }
}
