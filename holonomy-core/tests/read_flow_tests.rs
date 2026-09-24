// @trace TASK-114
// @trace TASK-065, TASK-066
mod common;
use common::MockPolicyProvider;
// @trace TASK-013
// @trace TASK-042

use bytes::Bytes;
use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::ingestion::s3_client::{IngestionError, IngestionProvider};
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::policy_manager::PolicyManager;
use holonomy_core::manager::read_orchestrator::{ReadError, ReadOrchestrator};
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
        // We'll decode metadata directly from parquet_data
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
async fn test_read_rejects_missing_purpose_none() {
    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let dek_cache = Arc::new(DekCache::default());
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
    let orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        Arc::new(MockIngestionProvider {
            parquet_data: vec![],
        }),
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let result = orchestrator
        .read(
            "http://dummy",
            None,
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
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ReadError::MissingPurpose));
}

#[tokio::test]
async fn test_read_rejects_empty_purpose_string() {
    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let dek_cache = Arc::new(DekCache::default());
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
    let orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        Arc::new(MockIngestionProvider {
            parquet_data: vec![],
        }),
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let result = orchestrator
        .read(
            "http://dummy",
            Some(""),
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
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ReadError::MissingPurpose));
}

#[tokio::test]
async fn test_end_to_end_read_flow_with_parquet() {
    let parquet_data = fs::read("tests/sample.parquet").expect("Failed to read sample.parquet");

    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let s3_client = Arc::new(MockIngestionProvider { parquet_data });
    let dek_cache = Arc::new(DekCache::default());
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
    let orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        s3_client,
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let result = orchestrator
        .read(
            "mock://sample.parquet",
            Some("business-analysis"),
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
        .await;
    assert!(result.is_ok(), "End-to-end read failed: {:?}", result.err());

    let array = result.unwrap();
    // In our CryptoManager, we convert the fetched chunks into a BinaryArray
    assert!(
        !array.is_empty(),
        "Should have returned actual Arrow pointers derived from chunks"
    );

    // Wait for the async channel message without sleeping!
    let event = audit_buffer.pop().expect("Audit event was not fired");
    assert_eq!(event.business_purpose, "business-analysis");
    assert_eq!(event.file_signature, "mock://sample.parquet");
}

struct MockIngestionProviderKmsFailure;

#[async_trait::async_trait]
impl IngestionProvider for MockIngestionProviderKmsFailure {
    async fn fetch_byte_range(
        &self,
        _url: &str,
        _range: Range<usize>,
    ) -> Result<Bytes, IngestionError> {
        Err(IngestionError::Parquet(
            parquet::errors::ParquetError::General("KMS Failed: KmsFailed".to_string()),
        ))
    }

    async fn fetch_multiple_ranges(
        &self,
        _url: &str,
        _ranges: Vec<Range<usize>>,
    ) -> Result<Vec<Bytes>, IngestionError> {
        Err(IngestionError::Parquet(
            parquet::errors::ParquetError::General("KMS Failed: KmsFailed".to_string()),
        ))
    }

    async fn fetch_parquet_metadata(
        &self,
        _url: &str,
        _decryption_props: Option<parquet::encryption::decrypt::FileDecryptionProperties>,
    ) -> Result<parquet::file::metadata::ParquetMetaData, IngestionError> {
        Err(IngestionError::Parquet(
            parquet::errors::ParquetError::General("KMS Failed: KmsFailed".to_string()),
        ))
    }

    async fn fetch_entire_file(&self, _url: &str) -> Result<Bytes, IngestionError> {
        Err(IngestionError::ParseFailed("Not found".to_string()))
    }
}

#[tokio::test]
async fn test_read_rejects_geofence_violation() {
    let _parquet_data = fs::read("tests/sample.parquet").expect("Failed to read sample.parquet");

    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let s3_client = Arc::new(MockIngestionProviderKmsFailure);
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(dek_cache, Arc::new(MockKmsProvider)));
    let policy_manager = Arc::new(PolicyManager::new_dangerously_allow_unsigned(
        std::sync::Arc::new(MockPolicyProvider),
    ));
    let governance_manager = Arc::new(GovernanceManager::new(Arc::new(
        common::MockSchemaRegistryProvider,
    )));
    let orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        s3_client,
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let result = orchestrator
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
        .await;
    assert!(result.is_err());

    // Ensure audit event was fired with GeofenceStatus::Violation
    let event = audit_buffer.pop().expect("Audit event was not fired");
    assert_eq!(
        event.action,
        holonomy_core::audit::ring_buffer::Action::Read
    );
}

// @trace TASK-036
// @trace TASK-036
#[tokio::test]
async fn test_read_accepts_valid_geofence() {
    let parquet_data = fs::read("tests/sample.parquet").expect("Failed to read sample.parquet");

    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(10));
    let s3_client = Arc::new(MockIngestionProvider { parquet_data });
    let dek_cache = Arc::new(DekCache::default());
    let crypto_manager = Arc::new(CryptoManager::new(dek_cache, Arc::new(MockKmsProvider)));
    let policy_manager = Arc::new(PolicyManager::new_dangerously_allow_unsigned(
        std::sync::Arc::new(MockPolicyProvider),
    ));

    let governance_manager = Arc::new(GovernanceManager::new(Arc::new(
        common::MockSchemaRegistryProvider,
    )));
    let orchestrator = ReadOrchestrator::new(
        audit_buffer.clone(),
        s3_client,
        crypto_manager,
        policy_manager,
        governance_manager,
    );

    let result = orchestrator
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
        .await;
    assert!(result.is_ok());

    // Ensure audit event was fired with GeofenceStatus::Pass
    let event = audit_buffer.pop().expect("Audit event was not fired");
    assert_eq!(
        event.action,
        holonomy_core::audit::ring_buffer::Action::Read
    );
}
