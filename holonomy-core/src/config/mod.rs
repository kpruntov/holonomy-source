// @trace TASK-027
// @trace TASK-033
// @trace TASK-128
// @trace TASK-130
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod resolver;

/// Top-level configuration structure representing the TOML file content.
/// Fields are optional to allow for hierarchical merging.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Configuration {
    pub kms: Option<KmsConfig>,
    pub policy: Option<PolicyConfig>,
    pub storage: Option<StorageConfig>,
    pub auth: Option<AuthConfig>,
    pub telemetry: Option<TelemetryConfig>,
    pub license: Option<LicenseConfig>,
}

/// License-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseConfig {
    pub key: Option<String>,
}

/// KMS-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KmsConfig {
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub key_id: Option<String>,
    pub region: Option<String>,
}

/// Global storage configuration for S3 backends.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    pub endpoint: Option<String>,
    pub region: Option<String>,
}

/// Policy and caching configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    pub central_bucket: Option<String>,
    pub cache_ttl_hours: Option<u32>,
    pub hash_salt: Option<String>,
    pub public_key: Option<String>,
}

/// Authentication and OIDC configuration.
// @trace TASK-133
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    pub provider: Option<String>,
    pub jwks_url: Option<String>,
    pub audience: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub credential_file: Option<String>,
}

/// Telemetry configuration for the audit broadcaster.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryConfig {
    pub endpoint: Option<String>,
    pub auth_token: Option<String>,
}

/// Errors that can occur during configuration parsing or validation.
#[derive(Debug)]
pub enum ConfigError {
    TomlError(String),
    SemanticError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::TomlError(e) => write!(f, "TOML Parse Error: {}", e),
            ConfigError::SemanticError(e) => write!(f, "Semantic Configuration Error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Configuration {
    /// Parses a TOML string into the Configuration structure.
    /// Encapsulates the TOML crate dependency.
    ///
    /// # Examples
    ///
    /// ```
    /// use holonomy_core::config::Configuration;
    ///
    /// let toml_str = r#"
    /// [kms]
    /// endpoint = "https://kms.eu-west-1.amazonaws.com"
    /// region = "eu-west-1"
    /// "#;
    ///
    /// let config = Configuration::from_toml(toml_str).expect("Valid TOML");
    /// assert_eq!(config.kms.unwrap().region.unwrap(), "eu-west-1");
    /// ```
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::TomlError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::resolver::{get_config, init_overrides, resolve_configuration};
    use crate::config::{Configuration, KmsConfig};
    use std::env;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_parse_valid_toml() {
        let toml_content = r#"
    [kms]
    provider = "aws"
    endpoint = "https://kms.eu-west-1.amazonaws.com"
    key_id = "arn:123"
    region = "eu-west-1"
    
    [policy]
    central_bucket = "s3://company-governance-vault/policies/"
    cache_ttl_hours = 48
    hash_salt = "super-secret"
    public_key = "04abcd..."
    
    [auth]
    jwks_url = "https://idp.example.com/.well-known/jwks.json"
    audience = "holonomy-api"
    issuer = "https://idp.example.com"
    client_id = "holonomy-cli"
    credential_file = "/tmp/creds"
    "#;

        let config = Configuration::from_toml(toml_content).expect("Failed to parse TOML");

        let kms = config.kms.expect("Missing kms block");
        assert_eq!(kms.provider, Some("aws".to_string()));
        assert_eq!(
            kms.endpoint,
            Some("https://kms.eu-west-1.amazonaws.com".to_string())
        );
        assert_eq!(kms.key_id, Some("arn:123".to_string()));
        assert_eq!(kms.region, Some("eu-west-1".to_string()));

        let policy = config.policy.expect("Missing policy block");
        assert_eq!(
            policy.central_bucket,
            Some("s3://company-governance-vault/policies/".to_string())
        );
        assert_eq!(policy.cache_ttl_hours, Some(48));
        assert_eq!(policy.hash_salt, Some("super-secret".to_string()));
        assert_eq!(policy.public_key, Some("04abcd...".to_string()));
        assert!(config.telemetry.is_none());
        
        let auth = config.auth.expect("Missing auth block");
        assert_eq!(auth.audience, Some("holonomy-api".to_string()));
    }

    #[test]
    fn test_parse_partial_toml() {
        let toml_content = r#"
    [kms]
    endpoint = "https://kms.eu-west-1.amazonaws.com"
    "#;

        let config = Configuration::from_toml(toml_content).expect("Failed to parse TOML");

        let kms = config.kms.expect("Missing kms block");
        assert_eq!(
            kms.endpoint,
            Some("https://kms.eu-west-1.amazonaws.com".to_string())
        );
        assert_eq!(kms.region, None); // Should be None, not eagerly defaulted

        assert!(config.policy.is_none());
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let toml_content = r#"
    [kms
    endpoint = "invalid"
    "#;

        let result = Configuration::from_toml(toml_content);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("TOML Parse Error"));
    }

    #[test]
    fn test_parse_invalid_types() {
        let toml_content = r#"
    [policy]
    cache_ttl_hours = "forty-eight"
    "#;

        let result = Configuration::from_toml(toml_content);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid type: string \"forty-eight\", expected u32"));
    }

    #[test]
    fn test_resolution_hierarchy() {
        let _lock = ENV_MUTEX.lock().unwrap();

        // 1. Setup Environment Variables safely
        unsafe {
            env::set_var("HOLONOMY_KMS_ENDPOINT", "env_kms_endpoint");
            env::set_var("HOLONOMY_POLICY_BUCKET", "env_policy_bucket");
            env::set_var("HOLONOMY_CACHE_TTL_HOURS", "12");
        }

        // 2. Setup Programmatic Overrides
        let programmatic = Configuration {
            kms: Some(KmsConfig {
                provider: None,
                endpoint: Some("prog_kms_endpoint".to_string()),
                key_id: None,
                region: None,
            }),
            policy: None,
            auth: None,
            telemetry: None,
            storage: None,
            license: None,
        };

        // 3. Setup TOML file content
        let toml_content = r#"
    [kms]
    region = "toml_region"
    [policy]
    cache_ttl_hours = 48
    "#;

        // Resolve
        let resolved = resolve_configuration(Some(programmatic), Some(toml_content));

        // Verify Hierarchy:
        // KMS Endpoint: Programmatic overrides Env
        assert_eq!(resolved.kms.endpoint, "prog_kms_endpoint");
        // KMS Region: TOML provides it, Prog/Env don't
        assert_eq!(resolved.kms.region, "toml_region");
        // Policy Bucket: Env provides it, Prog/TOML don't
        assert_eq!(resolved.policy.central_bucket, "env_policy_bucket");
        // Cache TTL: Env (12) overrides TOML (48)
        assert_eq!(resolved.policy.cache_ttl_hours, 12);

        // Cleanup
        unsafe {
            env::remove_var("HOLONOMY_KMS_ENDPOINT");
            env::remove_var("HOLONOMY_POLICY_BUCKET");
            env::remove_var("HOLONOMY_CACHE_TTL_HOURS");
        }
    }

    #[test]
    fn test_resolution_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Ensure clean environment
        unsafe {
            env::remove_var("HOLONOMY_KMS_ENDPOINT");
            env::remove_var("HOLONOMY_POLICY_BUCKET");
            env::remove_var("HOLONOMY_CACHE_TTL_HOURS");
        }
        let resolved = resolve_configuration(None, None);
        assert_eq!(resolved.policy.cache_ttl_hours, 24); // System Default
        assert_eq!(resolved.kms.endpoint, ""); // Empty default
    }

    #[test]
    fn test_singleton_lifecycle() {
        // 1. Initial explicit programmatic override
        let config1 = Configuration {
            kms: Some(KmsConfig {
                provider: None,
                endpoint: Some("singleton_kms_endpoint".to_string()),
                key_id: None,
                region: None,
            }),
            policy: None,
            auth: None,
            telemetry: None,
            storage: None,
            license: None,
        };

        let _ = init_overrides(config1);

        // 2. Fetch the config via the global singleton
        let resolved_1 = get_config();
        assert_eq!(resolved_1.kms.endpoint, "singleton_kms_endpoint");

        // Ensure standard Debug formats redact the sensitive endpoint
        let debug_str = format!("{:?}", resolved_1.kms);
        assert!(debug_str.contains("<REDACTED>"));
        assert!(!debug_str.contains("singleton_kms_endpoint"));

        // 3. Attempt a second initialization with different data
        let config2 = Configuration {
            kms: Some(KmsConfig {
                provider: None,
                endpoint: Some("ignored_kms_endpoint".to_string()),
                key_id: None,
                region: None,
            }),
            policy: None,
            auth: None,
            telemetry: None,
            storage: None,
            license: None,
        };

        let _ = init_overrides(config2);

        // 4. Verify that the singleton ignores the second initialization and returns the first value
        let resolved_2 = get_config();
        assert_eq!(resolved_2.kms.endpoint, "singleton_kms_endpoint");
    }
}
