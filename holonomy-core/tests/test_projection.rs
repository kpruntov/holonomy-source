// @trace TASK-065, TASK-066
mod common;
use common::MockPolicyProvider;
// @trace TASK-054
use bytes::Bytes;
use holonomy_core::audit::ring_buffer::AuditRingBuffer;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::ingestion::s3_client::{
    IngestionError, IngestionProvider, Predicate, PredicateValue,
};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::policy_manager::PolicyManager;
use holonomy_core::manager::scan_orchestrator::ScanOrchestrator;
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::fs::File;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

struct MockS3Client;

#[async_trait::async_trait]
impl IngestionProvider for MockS3Client {
    async fn fetch_byte_range(
        &self,
        _url: &str,
        _range: Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        Ok(Bytes::new())
    }

    async fn fetch_multiple_ranges(
        &self,
        _url: &str,
        _ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        Ok(vec![])
    }

    async fn fetch_entire_file(&self, _url: &str) -> Result<Bytes, IngestionError> {
        Err(IngestionError::ParseFailed("Not found".to_string()))
    }

    async fn fetch_parquet_metadata(
        &self,
        _url: &str,
        _decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, IngestionError> {
        let file = File::open("../dummy_data.parquet").unwrap();
        let reader = SerializedFileReader::new(file).unwrap();
        Ok(reader.metadata().clone())
    }
}

#[tokio::test]
async fn test_multi_column_projection_pruned() {
    let audit_buffer = Arc::new(AuditRingBuffer::new(100));
    let s3_client: Arc<dyn IngestionProvider> = Arc::new(MockS3Client);
    let dek_cache = Arc::new(DekCache::new(Duration::from_secs(3600)));
    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache,
        Arc::new(common::MockKmsProvider),
    ));
    let policy_manager = Arc::new(PolicyManager::new_dangerously_allow_unsigned(
        std::sync::Arc::new(MockPolicyProvider),
    ));
    let governance_manager = Arc::new(GovernanceManager::new(std::sync::Arc::new(
        common::MockSchemaRegistryProvider,
    )));

    let orchestrator = ScanOrchestrator::new(
        audit_buffer,
        s3_client,
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let columns = vec!["user_id".to_string(), "email".to_string()];

    // Prune all data by providing a predicate that is out of bounds
    // Based on dummy_data, if we use a predicate that filters out everything
    let predicates = vec![Predicate::Gt {
        column: "user_id".to_string(),
        value: PredicateValue::Int64(99999999), // out of bounds
    }];

    let mut reader = orchestrator
        .scan(
            vec!["s3://bucket/dummy_data.parquet".to_string()],
            Some("test purpose"),
            &holonomy_core::auth::jwt_validator::UserContext {
                sub: Some("user_hash_123".to_string()),
                client_id: None,
                email: None,
                principals: vec![],
                extra: std::collections::HashMap::new(),
            },
            Some(columns.clone()),
            &predicates,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // We can verify schema from the reader itself before moving it
    let schema = reader.schema();
    assert_eq!(schema.fields().len(), 2);
    assert_eq!(schema.field(0).name(), "user_id");
    assert_eq!(schema.field(1).name(), "email");

    let batch_opt = tokio::task::spawn_blocking(move || reader.next())
        .await
        .unwrap();

    // Verify it's an empty record batch or None with the full projected schema
    if let Some(Ok(batch)) = batch_opt {
        assert_eq!(batch.num_columns(), 2);
        assert_eq!(batch.num_rows(), 0);
    }
}
