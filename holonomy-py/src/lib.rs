// @trace TASK-119
// @trace TASK-083
// @trace TASK-129
// @trace TASK-078
// @trace TASK-006
// @trace TASK-067
// @trace TASK-066
// @trace TASK-029
// @trace TASK-030
// @trace TASK-014
// @trace TASK-075
// @trace TASK-077
// @trace TASK-089
// @trace TASK-093
// @trace TASK-142
// @trace TASK-095
// Python SDK bridge for Holonomy
use holonomy_core::config::resolver::{get_config, init_overrides};
use holonomy_core::config::{Configuration, KmsConfig, PolicyConfig};
use pyo3::prelude::*;

/// Initialize the configuration engine with programmatic overrides.
#[pyfunction]
#[pyo3(signature = (kms_provider=None, kms_endpoint=None, kms_key_id=None, kms_region=None, policy_bucket=None, cache_ttl_hours=None, hash_salt=None, public_key=None, identity_provider=None, jwks_url=None, audience=None, issuer=None, client_id=None, telemetry_endpoint=None, telemetry_token=None))]
#[allow(clippy::too_many_arguments)]
fn init(
    kms_provider: Option<String>,
    kms_endpoint: Option<String>,
    kms_key_id: Option<String>,
    kms_region: Option<String>,
    policy_bucket: Option<String>,
    cache_ttl_hours: Option<u32>,
    hash_salt: Option<String>,
    public_key: Option<String>,
    identity_provider: Option<String>,
    jwks_url: Option<String>,
    audience: Option<String>,
    issuer: Option<String>,
    client_id: Option<String>,
    telemetry_endpoint: Option<String>,
    telemetry_token: Option<String>,
) -> PyResult<()> {
    use holonomy_core::config::{AuthConfig, TelemetryConfig};
    let programmatic = Configuration {
        kms: if kms_provider.is_some() || kms_endpoint.is_some() || kms_key_id.is_some() || kms_region.is_some() {
            Some(KmsConfig {
                provider: kms_provider,
                endpoint: kms_endpoint,
                key_id: kms_key_id,
                region: kms_region,
            })
        } else {
            None
        },
        policy: if policy_bucket.is_some() || cache_ttl_hours.is_some() || hash_salt.is_some() || public_key.is_some() {
            Some(PolicyConfig {
                central_bucket: policy_bucket,
                cache_ttl_hours,
                hash_salt,
                public_key,
            })
        } else {
            None
        },
        storage: None,
        auth: if identity_provider.is_some() || jwks_url.is_some() || audience.is_some() || issuer.is_some() || client_id.is_some() {
            Some(AuthConfig {
                provider: identity_provider,
                jwks_url,
                audience,
                issuer,
                client_id,
                credential_file: None,
            })
        } else {
            None
        },
        telemetry: if telemetry_endpoint.is_some() || telemetry_token.is_some() {
            Some(TelemetryConfig {
                endpoint: telemetry_endpoint,
                auth_token: telemetry_token,
            })
        } else {
            None
        },
        license: None,
    };

    if init_overrides(programmatic).is_err() {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(
            "Holonomy is already initialized for this process",
        ));
    }
    Ok(())
}

use std::sync::Arc;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create Tokio runtime"))
}

use holonomy_core::crypto::dek_cache::DekCache;
use holonomy_core::ingestion::s3_client::S3Client;
use holonomy_core::manager::crypto_manager::CryptoManager;
use holonomy_core::manager::governance_manager::GovernanceManager;
use holonomy_core::manager::policy_manager::{PolicyManager, PolicyProvider};
use holonomy_core::manager::read_orchestrator::ReadOrchestrator;

use holonomy_core::manager::governance_manager::SchemaRegistryProvider;



struct DefaultSchemaRegistryProvider;
impl SchemaRegistryProvider for DefaultSchemaRegistryProvider {
    fn resolve_contract(&self, _target: &str) -> Option<String> {
        None
    }
}

struct MockKmsProvider;
#[async_trait::async_trait]
impl holonomy_core::manager::crypto_manager::KmsProvider for MockKmsProvider {
    async fn decrypt_dek(
        &self,
        wrapped_dek_ciphertext: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        if wrapped_dek_ciphertext.starts_with(b"kms_wrapped:") {
            Ok(wrapped_dek_ciphertext[b"kms_wrapped:".len()..].to_vec())
        } else {
            Err(holonomy_core::manager::crypto_manager::CryptoError::DecryptionFailed)
        }
    }

    async fn wrap_key(
        &self,
        key: &[u8],
        _context: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Vec<u8>, holonomy_core::manager::crypto_manager::CryptoError> {
        let mut wrapped = b"kms_wrapped:".to_vec();
        wrapped.extend_from_slice(key);
        Ok(wrapped)
    }
}

fn get_policy_manager(provider: Arc<dyn PolicyProvider>, config: &holonomy_core::config::resolver::ResolvedConfiguration) -> Result<Arc<PolicyManager>, String> {
    let pub_key_hex = config.policy.public_key.clone();
    if pub_key_hex.is_empty() {
        return Err("HOLONOMY_PUBLIC_KEY configuration is required for cryptographic verification".to_string());
    }
    let pub_key_bytes = hex::decode(&pub_key_hex)
        .map_err(|_| "HOLONOMY_PUBLIC_KEY must be a valid hex string".to_string())?;
    if pub_key_bytes.len() != 32 {
        return Err("HOLONOMY_PUBLIC_KEY must be exactly 32 bytes (64 hex characters)".to_string());
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&pub_key_bytes);
    Ok(Arc::new(PolicyManager::with_public_key(
        provider, key_array,
    )))
}

struct EngineState {
    audit_buffer: Arc<holonomy_core::audit::ring_buffer::AuditRingBuffer>,
    crypto_manager: Arc<CryptoManager>,
    policy_manager: Arc<PolicyManager>,
    governance_manager: Arc<GovernanceManager>,
}

static ENGINE_STATE: OnceLock<EngineState> = OnceLock::new();

fn build_engine_state(
    config: &holonomy_core::config::resolver::ResolvedConfiguration,
) -> Result<EngineState, String> {
    let audit_buffer = Arc::new(holonomy_core::audit::ring_buffer::AuditRingBuffer::new(
        1000,
    ));

    get_runtime().block_on(async {
        let _ = holonomy_core::manager::license_manager::resolve_and_verify_license(config).await;
    });

    if !config.telemetry.endpoint.is_empty() {
        let broadcaster = holonomy_core::audit::broadcaster::AuditBroadcaster::new(
            audit_buffer.clone(),
            holonomy_core::audit::broadcaster::SinkConfig::SaaS(
                config.telemetry.endpoint.clone(),
                config.telemetry.auth_token.clone(),
            ),
            100,
            std::time::Duration::from_millis(500),
            3,
        );
        let _guard = get_runtime().enter();
        broadcaster.start();

    }

    let dek_cache = Arc::new(DekCache::default());

    // @trace TASK-076
    let bucket = config.policy.central_bucket.clone();
    if bucket.is_empty() {
        return Err("HOLONOMY_POLICY_BUCKET environment variable is required".to_string());
    }

    let kms_provider: Arc<dyn holonomy_core::manager::crypto_manager::KmsProvider> = if bucket
        == "mock" || bucket == "local"
    {
        Arc::new(MockKmsProvider)
    } else {
        let provider_name = if config.kms.provider.is_empty() { "gcp".to_string() } else { config.kms.provider.clone() };
        match provider_name.to_lowercase().as_str() {
            "gcp" => {
                let key_id = config.kms.key_id.clone();
                if key_id.is_empty() {
                    return Err("FATAL: HOLONOMY_KMS_KEY_ID is required for GCP KMS".to_string());
                }

                let endpoint_url = config.kms.endpoint.clone();
                let endpoint = if endpoint_url.is_empty() {
                    None
                } else {
                    Some(endpoint_url)
                };

                let adapter = get_runtime().block_on(async {
                    holonomy_core::adapters::gcp::GcpAdapter::new(key_id, endpoint).await
                })
                .map_err(|e| format!("Failed to initialize GCP KMS Adapter. Are you logged in to GCP? Try running `gcloud auth application-default login`. Underlying error: {}", e))?;

                Arc::new(adapter)
            }
            "aws" => {
                let key_id = config.kms.key_id.clone();
                if key_id.is_empty() {
                    return Err("FATAL: HOLONOMY_KMS_KEY_ID is required for AWS KMS".to_string());
                }

                let adapter = get_runtime().block_on(async {
                    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
                    if !config.kms.endpoint.is_empty() {
                        loader = loader.endpoint_url(&config.kms.endpoint);
                    }
                    if !config.kms.region.is_empty() {
                        loader = loader.region(aws_config::Region::new(config.kms.region.clone()));
                    }
                    let aws_config = loader.load().await;
                    holonomy_core::adapters::aws::AwsAdapter::new(&aws_config, key_id)
                });
                Arc::new(adapter)
            }
            "vault" => {
                let key_id = config.kms.key_id.clone();
                if key_id.is_empty() {
                    return Err("FATAL: HOLONOMY_KMS_KEY_ID is required for Vault KMS".to_string());
                }
                let endpoint = config.kms.endpoint.clone();
                if endpoint.is_empty() {
                    return Err("FATAL: HOLONOMY_KMS_ENDPOINT is required for Vault KMS".to_string());
                }
                let token = std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "".to_string());
                if token.is_empty() {
                    return Err("FATAL: VAULT_TOKEN environment variable is required for Vault KMS".to_string());
                }
                let adapter = holonomy_core::adapters::vault::VaultAdapter::new(endpoint, token, key_id);
                Arc::new(adapter)
            }
            "azure" => return Err("FATAL: Azure Key Vault KMS adapter is not yet implemented.".to_string()),
            "mock" => Arc::new(MockKmsProvider),
            _ => return Err(format!(
                "FATAL: Unknown HOLONOMY_KMS_PROVIDER '{}'. Must be 'gcp', 'aws', or 'mock'.",
                provider_name
            )),
        }
    };

    let crypto_manager = Arc::new(CryptoManager::new(dek_cache, kms_provider));

    let storage_endpoint = if config.storage.endpoint.is_empty() { None } else { Some(config.storage.endpoint.clone()) };
    let storage_region = if config.storage.region.is_empty() { None } else { Some(config.storage.region.clone()) };

    let (policy_provider, override_pub_key): (
        Arc<dyn holonomy_core::manager::policy_manager::PolicyProvider>,
        Option<String>,
    ) = if bucket == "mock" || bucket == "local" {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let private_key = signing_key.to_bytes();
        let public_key_hex = holonomy_core::policy::signer::get_public_key_hex(&private_key);

        let provider = holonomy_core::policy::local_provider::LocalPolicyProvider::new(
            "./.holonomy/policies".to_string(),
            private_key,
        );
        (Arc::new(provider), Some(public_key_hex))
    } else {
        (
            Arc::new(holonomy_core::policy::s3_provider::S3PolicyProvider::new(
                bucket.clone(),
                storage_endpoint.clone(),
                storage_region.clone(),
            )),
            None,
        )
    };

    let mut modified_config = config.clone();
    if let Some(pk) = override_pub_key {
        modified_config.policy.public_key = pk;
    }
    let policy_manager = get_policy_manager(policy_provider, &modified_config)?;

    let schema_registry_provider: Arc<
        dyn holonomy_core::manager::governance_manager::SchemaRegistryProvider,
    > = if bucket == "mock" || bucket == "local" {
        Arc::new(DefaultSchemaRegistryProvider)
    } else {
        Arc::new(
            holonomy_core::schema::s3_registry::S3SchemaRegistryProvider::new(
                bucket.clone(),
                storage_endpoint.clone(),
                storage_region.clone(),
            ),
        )
    };

    let governance_manager = Arc::new(GovernanceManager::new(schema_registry_provider));

    Ok(EngineState {
        audit_buffer,
        crypto_manager,
        policy_manager,
        governance_manager,
    })
}

fn get_engine_state() -> Result<&'static EngineState, String> {
    if let Some(state) = ENGINE_STATE.get() {
        return Ok(state);
    }

    let config = holonomy_core::config::resolver::get_config();
    let state = build_engine_state(config)?;

    let _ = ENGINE_STATE.set(state);
    Ok(ENGINE_STATE.get().unwrap())
}

// @trace TASK-133
pub(crate) async fn parse_user_context(
    user_context_str: &str,
    config: &holonomy_core::config::resolver::ResolvedConfiguration,
) -> Result<holonomy_core::auth::jwt_validator::UserContext, String> {
    // Local Dev bypass: if mock mode and not a JWT token, treat as literal principal
    if config.auth.provider == "mock" && !user_context_str.starts_with("eyJ") {
        return Ok(holonomy_core::auth::jwt_validator::UserContext {
            sub: Some(user_context_str.to_string()),
            client_id: None,
            email: None,
            principals: vec![user_context_str.to_string()],
            extra: std::collections::HashMap::new(),
        });
    }

    let jwks_url = config.auth.jwks_url.clone();
    if jwks_url.is_empty() {
        return Err("MissingIdentityConfigurationError: jwks_url configuration is required. You must explicitly configure this to point to your Identity Provider's public keys.".to_string());
    }

    let audience = config.auth.audience.clone();
    let issuer = config.auth.issuer.clone();
    if issuer.is_empty() {
        return Err("MissingIdentityConfigurationError: issuer configuration is required. You must explicitly configure this to match your Identity Provider's issuer claim.".to_string());
    }

    let validator =
        holonomy_core::auth::jwt_validator::JwtValidator::new(jwks_url, audience, issuer);
    validator.validate_token(user_context_str).await
}

/// Reads data implicitly using the globally resolved configuration.
#[pyfunction]
#[pyo3(signature = (target, user_context=None, columns_to_read=None, purpose=None, filters_json=None, contract_json=None, assumed_role=None))]
fn read(
    target: String,
    user_context: Option<String>,
    columns_to_read: Option<Vec<String>>,
    purpose: Option<String>,
    filters_json: Option<String>,
    contract_json: Option<String>,
    assumed_role: Option<String>,
) -> PyResult<PyArrowType<arrow::array::ArrayData>> {
    let user_ctx_str = user_context.ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("MissingIdentityError: user_context is required")
    })?;
    let _ = filters_json; // intentionally unused for read
    let column_to_read = match columns_to_read {
        Some(mut cols) if !cols.is_empty() => cols.remove(0),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Must specify exactly one column for read",
            ));
        }
    };

    let rt = get_runtime();
    let state = get_engine_state().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

    let result = rt.block_on(async {
        let _config = get_config();
        let user_ctx = parse_user_context(&user_ctx_str, _config).await?;

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if !_config.storage.endpoint.is_empty() {
            loader = loader.endpoint_url(&_config.storage.endpoint);
        }
        if !_config.storage.region.is_empty() {
            loader = loader.region(aws_config::Region::new(_config.storage.region.clone()));
        }
        let aws_config = loader.load().await;

        let s3_client: Arc<dyn holonomy_core::ingestion::s3_client::IngestionProvider> =
            if target.starts_with("file://") {
                Arc::new(holonomy_core::ingestion::local_file_provider::LocalFileProvider)
            } else {
                Arc::new(S3Client::new(Some(aws_config)))
            };

        let orchestrator = ReadOrchestrator::new(
            state.audit_buffer.clone(),
            s3_client,
            state.crypto_manager.clone(),
            state.policy_manager.clone(),
            state.governance_manager.clone(),
        );

        let array = orchestrator
            .read(
                &target,
                purpose.as_deref(),
                &user_ctx,
                &column_to_read,
                contract_json.as_deref(),
                assumed_role.as_deref(),
                None,
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok::<arrow::array::ArrayData, String>(array.to_data().clone())
    });

    match result {
        Ok(data) => Ok(PyArrowType(data)),
        Err(err_msg) => Err(pyo3::exceptions::PyRuntimeError::new_err(err_msg)),
    }
}

use arrow::array::RecordBatchReader;
use holonomy_core::manager::scan_orchestrator::ScanOrchestrator;

/// Scans data lazily using the globally resolved configuration.
#[pyfunction]
#[pyo3(signature = (target, user_context=None, columns_to_read=None, purpose=None, filters_json=None, contract_json=None, assumed_role=None))]
fn scan(
    target: String,
    user_context: Option<String>,
    columns_to_read: Option<Vec<String>>,
    purpose: Option<String>,
    filters_json: Option<String>,
    contract_json: Option<String>,
    assumed_role: Option<String>,
) -> PyResult<PyArrowType<Box<dyn RecordBatchReader + Send>>> {
    let user_ctx_str = user_context.ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("MissingIdentityError: user_context is required")
    })?;
    // @trace TASK-052
    let _config = get_config();

    let rt = get_runtime();
    let state = get_engine_state().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

    let result = rt.block_on(async {
        let _config = get_config();
        let user_ctx = parse_user_context(&user_ctx_str, _config).await?;
        let predicates = if let Some(json) = filters_json {
            serde_json::from_str::<Vec<holonomy_core::ingestion::s3_client::Predicate>>(&json)
                .map_err(|e| format!("Failed to parse filters: {}", e))?
        } else {
            vec![]
        };

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if !_config.storage.endpoint.is_empty() {
            loader = loader.endpoint_url(&_config.storage.endpoint);
        }
        if !_config.storage.region.is_empty() {
            loader = loader.region(aws_config::Region::new(_config.storage.region.clone()));
        }
        let aws_config = loader.load().await;

        let s3_client: Arc<dyn holonomy_core::ingestion::s3_client::IngestionProvider> =
            if target.starts_with("file://") {
                Arc::new(holonomy_core::ingestion::local_file_provider::LocalFileProvider)
            } else {
                Arc::new(S3Client::new(Some(aws_config)))
            };

        let orchestrator = ScanOrchestrator::new(
            state.audit_buffer.clone(),
            s3_client,
            state.crypto_manager.clone(),
            state.policy_manager.clone(),
            state.governance_manager.clone(),
        );

        let reader = orchestrator
            .scan(
                vec![target.to_string()],
                purpose.as_deref(),
                &user_ctx,
                columns_to_read,
                &predicates,
                contract_json.as_deref(),
                None,
                assumed_role.as_deref(),
                None,
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok::<Box<dyn RecordBatchReader + Send>, String>(reader)
    });

    match result {
        Ok(stream) => Ok(PyArrowType(stream)),
        Err(err_msg) => Err(pyo3::exceptions::PyRuntimeError::new_err(err_msg)),
    }
}

use arrow::pyarrow::PyArrowType;
use arrow::record_batch::RecordBatch;
use holonomy_core::crypto::pme_encrypt::S3MultipartUploader;
use holonomy_core::manager::write_orchestrator::WriteOrchestrator;

/// Writes data implicitly using the globally resolved configuration.
/// Parses the target to extract bucket, key, and potential endpoint
fn parse_target(target: &str, config_endpoint: Option<String>) -> (String, String, Option<String>) {
    if target.starts_with("http://") || target.starts_with("https://") {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() >= 5 {
            let endpoint = format!("{}//{}", parts[0], parts[2]);
            let bucket = parts[3].to_string();
            let key = parts[4..].join("/");
            return (bucket, key, Some(endpoint));
        }
    } else if target.starts_with("s3://") {
        let parts: Vec<&str> = target.split('/').collect();
        if parts.len() >= 4 {
            let bucket = parts[2].to_string();
            let key = parts[3..].join("/");
            return (bucket, key, config_endpoint);
        }
    }
    (
        "default-bucket".to_string(),
        target.to_string(),
        config_endpoint,
    )
}

/// Writes data implicitly using the globally resolved configuration.
#[pyfunction]
#[pyo3(signature = (batch, target, user_context=None, purpose=None, contract_json=None))]
fn write(
    batch: PyArrowType<RecordBatch>,
    target: String,
    user_context: Option<String>,
    purpose: Option<String>,
    contract_json: Option<String>,
) -> PyResult<String> {
    let user_ctx_str = user_context.ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err("MissingIdentityError: user_context is required")
    })?;

    let rt = get_runtime();
    let state = get_engine_state().map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

    let result = rt.block_on(async {
        let config = get_config();
        let storage_endpoint = if config.storage.endpoint.is_empty() { None } else { Some(config.storage.endpoint.clone()) };
        let storage_region = if config.storage.region.is_empty() { None } else { Some(config.storage.region.clone()) };

        let (bucket, key, endpoint) = parse_target(&target, storage_endpoint);
        let uploader: Arc<dyn holonomy_core::crypto::pme_encrypt::StorageUploader> = if target.starts_with("file://") {
            Arc::new(crate::writer::MockStorageUploader {
                target_path: target.replace("file://", ""),
            })
        } else {
            Arc::new(
                S3MultipartUploader::new(bucket, endpoint, storage_region, None, None).await
            )
        }; // @trace TASK-057
        
        let orchestrator = WriteOrchestrator::new(
            state.audit_buffer.clone(),
            state.crypto_manager.clone(),
            uploader,
            state.governance_manager.clone(),
            state.policy_manager.clone(),
        );

        orchestrator
            .write(
                &batch.0,
                &key,
                purpose.as_deref(),
                &user_ctx_str,
                contract_json.as_deref(),
            )
            .await
            .map_err(|e| e.to_string())?;

        if target.starts_with("file://") {
            Ok::<String, String>("Secure Write Successful. File written to local disk.".to_string())
        } else {
            Ok::<String, String>("Secure Write Successful. File uploaded to S3.".to_string())
        }
    });

    match result {
        Ok(msg) => Ok(msg),
        Err(err_msg) => Err(pyo3::exceptions::PyRuntimeError::new_err(err_msg)),
    }
}

/// Helper method to expose active config for testing
#[pyfunction]
fn _get_active_config() -> PyResult<(String, String, String, u32)> {
    let config = get_config();
    Ok((
        config.kms.endpoint.clone(),
        config.kms.region.clone(),
        config.policy.central_bucket.clone(),
        config.policy.cache_ttl_hours,
    ))
}

#[pyfunction]
fn _cli_main(args: Vec<String>) -> PyResult<()> {
    let rt = get_runtime();
    rt.block_on(async {
        holonomy_cli::cli::run_cli_with_args(args).await;
    });
    Ok(())
}

pub mod writer;

/// A Python module implemented in Rust.
#[pymodule]
fn _holonomy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<writer::Writer>()?;
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(read, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(write, m)?)?;
    m.add_function(wrap_pyfunction!(_get_active_config, m)?)?;
    m.add_function(wrap_pyfunction!(_cli_main, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_state_requires_bucket() {
        use holonomy_core::config::resolver::{
            ResolvedConfiguration, ResolvedKmsConfig, ResolvedPolicyConfig, ResolvedAuthConfig, ResolvedTelemetryConfig,
        };

        let mut mock_config = ResolvedConfiguration {
            kms: ResolvedKmsConfig {
                provider: "mock".to_string(),
                endpoint: "".to_string(),
                key_id: "".to_string(),
                region: "".to_string(),
            },
            policy: ResolvedPolicyConfig {
                central_bucket: "".to_string(),
                hash_salt: "dummy_salt".to_string(),
                cache_ttl_hours: 24,
                public_key: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            auth: ResolvedAuthConfig {
                provider: "".to_string(),
                jwks_url: "".to_string(),
                audience: "".to_string(),
                issuer: "".to_string(),
                client_id: "".to_string(),
                credential_file: None,
            },
            telemetry: ResolvedTelemetryConfig {
                endpoint: "".to_string(),
                auth_token: None,
            },
            storage: holonomy_core::config::resolver::ResolvedStorageConfig {
                endpoint: "".to_string(),
                region: "".to_string(),
            },
            license: Default::default(),
        };

        // 1. Test missing bucket fails
        let result = build_engine_state(&mock_config);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "HOLONOMY_POLICY_BUCKET environment variable is required"
        );

        // 2. Test valid bucket succeeds
        mock_config.policy.central_bucket = "test-bucket".to_string();
        let result = build_engine_state(&mock_config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_parse_user_context_jwt() {
        let mock_config = holonomy_core::config::resolver::ResolvedConfiguration {
            kms: holonomy_core::config::resolver::ResolvedKmsConfig {
                provider: "".to_string(), endpoint: "".to_string(), key_id: "".to_string(), region: "".to_string(),
            },
            policy: holonomy_core::config::resolver::ResolvedPolicyConfig {
                central_bucket: "".to_string(), hash_salt: "".to_string(), cache_ttl_hours: 24, public_key: "".to_string(),
            },
            auth: holonomy_core::config::resolver::ResolvedAuthConfig {
                provider: "".to_string(),
                jwks_url: "http://localhost:8080/jwks".to_string(),
                audience: "".to_string(),
                issuer: "http://localhost:8080/issuer".to_string(),
                client_id: "".to_string(),
                credential_file: None,
            },
            telemetry: holonomy_core::config::resolver::ResolvedTelemetryConfig {
                endpoint: "".to_string(), auth_token: None,
            },
            storage: holonomy_core::config::resolver::ResolvedStorageConfig {
                endpoint: "".to_string(), region: "".to_string(),
            },
            license: Default::default(),
        };
        // We expect an error because it's an invalid JWT format
        let raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwi.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let result = crate::parse_user_context(raw_jwt, &mock_config).await;
        assert!(result.is_err(), "Should fail with invalid JWT");
        let err = result.unwrap_err();
        assert!(
            err.contains("JWT validation failed")
                || err.contains("Invalid JWT")
                || err.contains("MissingIdentityConfigurationError"),
            "Unexpected error: {}",
            err
        );
    }
}
