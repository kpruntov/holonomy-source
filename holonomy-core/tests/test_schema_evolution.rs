// @trace TASK-065, TASK-066
mod common;
use common::MockPolicyProvider;
// @trace TASK-058
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

#[tokio::test]
async fn test_schema_evolution_padding() {
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

    let orchestrator = ScanOrchestrator::new(
        audit_buffer.clone(),
        s3_client.clone(),
        crypto_manager.clone(),
        policy_manager.clone(),
        governance_manager.clone(),
    );

    // Provide a contract JSON with a new missing column "missing_status"
    let contract_json = r#"{
        "name": "EvolvedTest",
        "version": "1.1",
        "columns": [
            {"name": "id", "type": "int64", "required": true},
            {"name": "missing_status", "type": "string", "required": false}
        ]
    }"#;

    // Scan requesting columns that exist in parquet + the new missing column
    let mut reader_scan = orchestrator
        .scan(
            vec!["mock://test/partition.parquet".to_string()],
            Some("Business Purpose - Schema Evolution"),
            &holonomy_core::auth::jwt_validator::UserContext {
                sub: Some("test_user".to_string()),
                client_id: None,
                email: None,
                principals: vec![],
                extra: std::collections::HashMap::new(),
            },
            Some(vec!["id".to_string(), "missing_status".to_string()]),
            &[],
            Some(contract_json),
            None,
            None,
            None,
        )
        .await
        .expect("Scan failed");

    // Assert schema has both columns before moving reader
    let schema = reader_scan.schema();
    assert_eq!(schema.fields().len(), 2);
    assert_eq!(schema.field(0).name(), "id");
    assert_eq!(schema.field(1).name(), "missing_status");

    let batch = tokio::task::spawn_blocking(move || {
        reader_scan.next().unwrap().expect("Failed to get batch")
    })
    .await
    .unwrap();

    // Assert missing_status column is a NullArray
    let null_col = batch.column(1);
    assert_eq!(null_col.data_type(), &arrow::datatypes::DataType::Utf8);
    assert_eq!(null_col.null_count(), null_col.len());

    // Test ReadOrchestrator for the same missing column
    let read_orchestrator = ReadOrchestrator::new(
        audit_buffer,
        s3_client,
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let read_array = read_orchestrator
        .read(
            "mock://test/partition.parquet",
            Some("Business Purpose - Schema Evolution"),
            &holonomy_core::auth::jwt_validator::UserContext {
                sub: Some("test_user".to_string()),
                client_id: None,
                email: None,
                principals: vec![],
                extra: std::collections::HashMap::new(),
            },
            "missing_status",
            Some(contract_json),
            None,
            None,
        )
        .await
        .expect("Read failed");

    assert_eq!(read_array.data_type(), &arrow::datatypes::DataType::Utf8);
    assert_eq!(read_array.null_count(), read_array.len());
}
