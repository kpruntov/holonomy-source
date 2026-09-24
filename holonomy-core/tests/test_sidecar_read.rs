// @trace TASK-123
mod common;


use holonomy_core::audit::ring_buffer::AuditRingBuffer;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::ingestion::s3_client::IngestionProvider;
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::policy_manager::PolicyManager;
use holonomy_core::manager::scan_orchestrator::ScanOrchestrator;
use std::sync::Arc;
use tokio::sync::Mutex;
use async_trait::async_trait;

struct MockS3WithSidecar {
    pub sidecar_fetched: Arc<Mutex<bool>>,
}

#[async_trait]
impl IngestionProvider for MockS3WithSidecar {
    async fn fetch_byte_range(&self, _target: &str, _range: std::ops::Range<usize>) -> Result<bytes::Bytes, holonomy_core::ingestion::s3_client::IngestionError> {
        Err(holonomy_core::ingestion::s3_client::IngestionError::ParseFailed("Not found".into()))
    }

    async fn fetch_multiple_ranges(&self, _target: &str, _ranges: Vec<std::ops::Range<usize>>) -> Result<Vec<bytes::Bytes>, holonomy_core::ingestion::s3_client::IngestionError> {
        Err(holonomy_core::ingestion::s3_client::IngestionError::ParseFailed("Not found".into()))
    }

    async fn fetch_parquet_metadata(
        &self,
        _url: &str,
        _decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, holonomy_core::ingestion::s3_client::IngestionError> {
        Err(holonomy_core::ingestion::s3_client::IngestionError::ParseFailed("Not found".into()))
    }

    async fn fetch_entire_file(&self, target: &str) -> Result<bytes::Bytes, holonomy_core::ingestion::s3_client::IngestionError> {
        if target.ends_with("_holonomy_keys.json") {
            let mut fetched = self.sidecar_fetched.lock().await;
            *fetched = true;
            let json = r#"[
                {"purpose":"mock_purpose","column":"__footer__","wrapped_dek":"bW9jay13cmFwcGVkLWRlaw=="}
            ]"#;
            return Ok(bytes::Bytes::from(json));
        }
        Err(holonomy_core::ingestion::s3_client::IngestionError::ParseFailed("Not found".into()))
    }
}

#[tokio::test]
async fn test_sidecar_read() {
    let dek_cache = Arc::new(DekCache::new(std::time::Duration::from_secs(10)));
    let crypto_manager = Arc::new(CryptoManager::new(
        dek_cache.clone(),
        Arc::new(common::MockKmsProvider),
    ));

    let fetched = Arc::new(Mutex::new(false));
    let provider = Arc::new(MockS3WithSidecar {
        sidecar_fetched: fetched.clone(),
    });

    let orchestrator = ScanOrchestrator::new(
        Arc::new(AuditRingBuffer::new(10)),
        provider,
        crypto_manager,
        Arc::new(PolicyManager::new_dangerously_allow_unsigned(Arc::new(common::MockPolicyProvider))),
        Arc::new(GovernanceManager::new(Arc::new(common::MockSchemaRegistryProvider))),
    );

    let user_ctx = holonomy_core::auth::jwt_validator::UserContext {
        sub: Some("user1".into()),
        client_id: None,
        email: None,
        principals: vec!["role1".into()],
        extra: std::collections::HashMap::new(),
    };
    
    // We expect this to fail eventually because the Parquet file doesn't actually exist in our mock,
    // but it should first fetch the sidecar and try to parse it.
    let _ = orchestrator.scan(
        vec!["s3://bucket/partition/file.parquet".to_string()],
        Some("mock_purpose"),
        &user_ctx,
        None,
        &[],
        None,
        None,
        None,
        None,
    ).await;

    let was_fetched = *fetched.lock().await;
    assert!(was_fetched, "Should have fetched sidecar json");
}
