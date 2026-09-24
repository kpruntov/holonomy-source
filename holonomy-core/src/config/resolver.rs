// @trace TASK-028
// @trace TASK-128
// @trace TASK-130
use super::Configuration;
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

/// The fully resolved configuration structure (no Option fields).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Default)]
pub struct ResolvedConfiguration {
    pub kms: ResolvedKmsConfig,
    pub policy: ResolvedPolicyConfig,
    pub storage: ResolvedStorageConfig,
    pub auth: ResolvedAuthConfig,
    pub telemetry: ResolvedTelemetryConfig,
    pub license: ResolvedLicenseConfig,
}

#[derive(Debug, Clone, Zeroize, Default)]
pub struct ResolvedLicenseConfig {
    pub key: Option<String>,
}

#[derive(Clone, Zeroize, Default)]
pub struct ResolvedKmsConfig {
    pub provider: String,
    pub endpoint: String,
    pub key_id: String,
    pub region: String,
}

// Manually implement Debug to redact sensitive fields if any
impl fmt::Debug for ResolvedKmsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedKmsConfig")
            .field("provider", &self.provider)
            .field("endpoint", &"<REDACTED>")
            .field("key_id", &"<REDACTED>")
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Debug, Clone, Zeroize, Default)]
pub struct ResolvedPolicyConfig {
    pub central_bucket: String,
    pub cache_ttl_hours: u32,
    pub hash_salt: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Zeroize, Default)]
pub struct ResolvedStorageConfig {
    pub endpoint: String,
    pub region: String,
}

// @trace TASK-133
#[derive(Debug, Clone, Zeroize, Default)]
pub struct ResolvedAuthConfig {
    pub provider: String,
    pub jwks_url: String,
    pub audience: String,
    pub issuer: String,
    pub client_id: String,
    pub credential_file: Option<String>,
}

#[derive(Clone, Zeroize, Default)]
pub struct ResolvedTelemetryConfig {
    pub endpoint: String,
    pub auth_token: Option<String>,
}

impl fmt::Debug for ResolvedTelemetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedTelemetryConfig")
            .field("endpoint", &self.endpoint)
            .field("auth_token", &if self.auth_token.is_some() { "<REDACTED>" } else { "None" })
            .finish()
    }
}

/// The global Singleton for the Configuration Engine.
static CONFIG_RESOLVER: OnceLock<ResolvedConfiguration> = OnceLock::new();

/// Exposes O(1) thread-safe access to the resolved configuration.
pub fn get_config() -> &'static ResolvedConfiguration {
    CONFIG_RESOLVER.get_or_init(|| {
        resolve_configuration(None, None)
    })
}

/// Error returned when the configuration singleton is initialized more than once.
#[derive(Debug)]
pub struct ConfigInitError;

impl fmt::Display for ConfigInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Configuration has already been initialized")
    }
}

impl std::error::Error for ConfigInitError {}

/// Allows programmatic overrides to be fed into the resolver before the first read.
pub fn init_overrides(programmatic: Configuration) -> Result<(), ConfigInitError> {
    let resolved = resolve_configuration(Some(programmatic), None);
    CONFIG_RESOLVER.set(resolved).map_err(|_| ConfigInitError)
}

fn merge_config(base: &mut Configuration, over: Configuration) {
    if let Some(k) = over.kms {
        let mut b = base.kms.take().unwrap_or_default();
        if k.provider.is_some() { b.provider = k.provider; }
        if k.endpoint.is_some() { b.endpoint = k.endpoint; }
        if k.key_id.is_some() { b.key_id = k.key_id; }
        if k.region.is_some() { b.region = k.region; }
        base.kms = Some(b);
    }
    if let Some(p) = over.policy {
        let mut b = base.policy.take().unwrap_or_default();
        if p.central_bucket.is_some() { b.central_bucket = p.central_bucket; }
        if p.cache_ttl_hours.is_some() { b.cache_ttl_hours = p.cache_ttl_hours; }
        if p.hash_salt.is_some() { b.hash_salt = p.hash_salt; }
        if p.public_key.is_some() { b.public_key = p.public_key; }
        base.policy = Some(b);
    }
    if let Some(s) = over.storage {
        let mut b = base.storage.take().unwrap_or_default();
        if s.endpoint.is_some() { b.endpoint = s.endpoint; }
        if s.region.is_some() { b.region = s.region; }
        base.storage = Some(b);
    }
    if let Some(a) = over.auth {
        let mut b = base.auth.take().unwrap_or_default();
        if a.provider.is_some() { b.provider = a.provider; }
        if a.jwks_url.is_some() { b.jwks_url = a.jwks_url; }
        if a.audience.is_some() { b.audience = a.audience; }
        if a.issuer.is_some() { b.issuer = a.issuer; }
        if a.client_id.is_some() { b.client_id = a.client_id; }
        if a.credential_file.is_some() { b.credential_file = a.credential_file; }
        base.auth = Some(b);
    }
    if let Some(t) = over.telemetry {
        let mut b = base.telemetry.take().unwrap_or_default();
        if t.endpoint.is_some() { b.endpoint = t.endpoint; }
        if t.auth_token.is_some() { b.auth_token = t.auth_token; }
        base.telemetry = Some(b);
    }
    if let Some(l) = over.license {
        let mut b = base.license.take().unwrap_or_default();
        if l.key.is_some() { b.key = l.key; }
        base.license = Some(b);
    }
}

/// Performs the hierarchical resolution loop (P1-P6).
pub fn resolve_configuration(
    programmatic: Option<Configuration>,
    toml_override: Option<&str>, // For testing
) -> ResolvedConfiguration {
    let mut merged = Configuration::default();

    // Layer 5: System TOML
    if let Ok(content) = fs::read_to_string("/etc/holonomy/config.toml")
        && let Ok(cfg) = Configuration::from_toml(&content) {
            merge_config(&mut merged, cfg);
        }

    // Layer 4: User TOML
    let xdg_config_home = env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
        let home = env::var("HOME").unwrap_or_else(|_| "".to_string());
        format!("{}/.config", home)
    });
    let user_toml_path = PathBuf::from(xdg_config_home).join("holonomy/config.toml");
    if let Ok(content) = fs::read_to_string(user_toml_path)
        && let Ok(cfg) = Configuration::from_toml(&content) {
            merge_config(&mut merged, cfg);
        }

    // Layer 3: Project TOML (Crawl upwards from current directory)
    if let Ok(mut current_dir) = env::current_dir() {
        loop {
            let toml_path = current_dir.join(".holonomy.toml");
            if let Ok(content) = fs::read_to_string(&toml_path) {
                if let Ok(cfg) = Configuration::from_toml(&content) {
                    merge_config(&mut merged, cfg);
                }
                break; // Found the nearest project config, stop searching
            }
            if !current_dir.pop() {
                break; // Reached the root directory without finding the file
            }
        }
    }
    
    // Fallback/Testing TOML Override
    if let Some(content) = toml_override
        && let Ok(cfg) = Configuration::from_toml(content) {
            merge_config(&mut merged, cfg);
        }

    // Layer 2: Environment Variables
    let mut env_cfg = Configuration::default();
    
    let mut env_kms = super::KmsConfig::default();
    if let Ok(v) = env::var("HOLONOMY_KMS_PROVIDER") { env_kms.provider = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_KMS_ENDPOINT") { env_kms.endpoint = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_KMS_KEY_ID") { env_kms.key_id = Some(v); }
    env_cfg.kms = Some(env_kms);
    
    let mut env_pol = super::PolicyConfig::default();
    if let Ok(v) = env::var("HOLONOMY_POLICY_BUCKET") { env_pol.central_bucket = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_CACHE_TTL_HOURS") && let Ok(n) = v.parse() { env_pol.cache_ttl_hours = Some(n); }
    if let Ok(v) = env::var("HOLONOMY_HASH_SALT") { env_pol.hash_salt = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_PUBLIC_KEY") { env_pol.public_key = Some(v); }
    env_cfg.policy = Some(env_pol);
    
    let mut env_storage = super::StorageConfig::default();
    if let Ok(v) = env::var("HOLONOMY_STORAGE_ENDPOINT") { env_storage.endpoint = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_STORAGE_REGION") { env_storage.region = Some(v); }
    env_cfg.storage = Some(env_storage);

    let mut env_auth = super::AuthConfig::default();
    if let Ok(v) = env::var("HOLONOMY_JWKS_URL") { env_auth.jwks_url = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_AUDIENCE") { env_auth.audience = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_ISSUER") { env_auth.issuer = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_CLIENT_ID") { env_auth.client_id = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_CREDENTIAL_FILE") { env_auth.credential_file = Some(v); }
    env_cfg.auth = Some(env_auth);
    
    let mut env_tel = super::TelemetryConfig::default();
    if let Ok(v) = env::var("HOLONOMY_TELEMETRY_ENDPOINT") { env_tel.endpoint = Some(v); }
    if let Ok(v) = env::var("HOLONOMY_TELEMETRY_TOKEN") { env_tel.auth_token = Some(v); }
    env_cfg.telemetry = Some(env_tel);

    let mut env_lic = super::LicenseConfig::default();
    if let Ok(v) = env::var("HOLONOMY_LICENSE_KEY") { env_lic.key = Some(v); }
    env_cfg.license = Some(env_lic);

    merge_config(&mut merged, env_cfg);

    // Layer 1: Programmatic overrides
    if let Some(prog) = programmatic {
        merge_config(&mut merged, prog);
    }

    // Layer 6: Finalize with Defaults
    let mut central_bucket = merged.policy.as_ref().and_then(|p| p.central_bucket.clone()).unwrap_or_default();
    if let Some(stripped) = central_bucket.strip_prefix("s3://") {
        central_bucket = stripped.to_string();
    } else if let Some(stripped) = central_bucket.strip_prefix("r2://") {
        central_bucket = stripped.to_string();
    }

    ResolvedConfiguration {
        kms: ResolvedKmsConfig { 
            provider: merged.kms.as_ref().and_then(|k| k.provider.clone()).unwrap_or_default(),
            endpoint: merged.kms.as_ref().and_then(|k| k.endpoint.clone()).unwrap_or_default(),
            key_id: merged.kms.as_ref().and_then(|k| k.key_id.clone()).unwrap_or_default(),
            region: merged.kms.as_ref().and_then(|k| k.region.clone()).unwrap_or_default(),
        },
        policy: ResolvedPolicyConfig {
            central_bucket,
            cache_ttl_hours: merged.policy.as_ref().and_then(|p| p.cache_ttl_hours).unwrap_or(24),
            hash_salt: merged.policy.as_ref().and_then(|p| p.hash_salt.clone()).unwrap_or_else(|| "default-insecure-salt".to_string()),
            public_key: merged.policy.as_ref().and_then(|p| p.public_key.clone()).unwrap_or_default(),
        },
        storage: ResolvedStorageConfig {
            endpoint: merged.storage.as_ref().and_then(|s| s.endpoint.clone()).unwrap_or_default(),
            region: merged.storage.as_ref().and_then(|s| s.region.clone()).unwrap_or_default(),
        },
        auth: ResolvedAuthConfig {
            provider: merged.auth.as_ref().and_then(|a| a.provider.clone()).unwrap_or_default(),
            jwks_url: merged.auth.as_ref().and_then(|a| a.jwks_url.clone()).unwrap_or_default(),
            audience: merged.auth.as_ref().and_then(|a| a.audience.clone()).unwrap_or_default(),
            issuer: merged.auth.as_ref().and_then(|a| a.issuer.clone()).unwrap_or_default(),
            client_id: merged.auth.as_ref().and_then(|a| a.client_id.clone()).unwrap_or_default(),
            credential_file: merged.auth.as_ref().and_then(|a| a.credential_file.clone()),
        },
        telemetry: ResolvedTelemetryConfig {
            endpoint: merged.telemetry.as_ref().and_then(|t| t.endpoint.clone()).unwrap_or_default(),
            auth_token: merged.telemetry.as_ref().and_then(|t| t.auth_token.clone()),
        },
        license: ResolvedLicenseConfig {
            key: merged.license.as_ref().and_then(|l| l.key.clone()),
        },
    }
}
