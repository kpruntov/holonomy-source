// @trace TASK-069
// @trace FR-009
// @trace TASK-097

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

// @trace TASK-093
/// Identity attributes mapped to the local user context structure
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UserContext {
    pub sub: Option<String>,
    pub client_id: Option<String>,
    pub email: Option<String>,
    pub principals: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for UserContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawContext {
            sub: Option<String>,
            client_id: Option<String>,
            email: Option<String>,
            #[serde(default)]
            groups: Vec<String>,
            #[serde(default)]
            roles: Vec<String>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let raw = RawContext::deserialize(deserializer)?;
        let mut principals = std::collections::HashSet::new();

        if let Some(ref sub) = raw.sub {
            principals.insert(sub.clone());
        }
        if let Some(ref client_id) = raw.client_id {
            principals.insert(client_id.clone());
        }

        for g in raw.groups {
            principals.insert(g);
        }
        for r in raw.roles {
            principals.insert(r);
        }

        if let Some(realm_access) = raw.extra.get("realm_access")
            && let Some(roles) = realm_access.get("roles")
            && let Some(arr) = roles.as_array()
        {
            for v in arr {
                if let Some(s) = v.as_str() {
                    principals.insert(s.to_string());
                }
            }
        }

        let mut principals_vec: Vec<String> = principals.into_iter().collect();
        principals_vec.sort();

        Ok(UserContext {
            sub: raw.sub,
            client_id: raw.client_id,
            email: raw.email,
            principals: principals_vec,
            extra: raw.extra,
        })
    }
}

impl UserContext {
    pub fn identity(&self) -> String {
        if let Some(sub) = &self.sub {
            sub.clone()
        } else if let Some(client_id) = &self.client_id {
            client_id.clone()
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

pub struct JwtValidator {
    pub jwks_url: String,
    pub client: Client,
    pub audience: String,
    pub issuer: String,
    jwks_cache: RwLock<HashMap<String, Jwk>>,
}

impl JwtValidator {
    pub fn new(jwks_url: String, audience: String, issuer: String) -> Self {
        Self {
            jwks_url,
            client: Client::new(),
            audience,
            issuer,
            jwks_cache: RwLock::new(HashMap::new()),
        }
    }

    async fn fetch_jwks(&self) -> Result<(), String> {
        let jwks: Jwks = if self.jwks_url.starts_with("file://") {
            let path = self.jwks_url.trim_start_matches("file://");
            let content = std::fs::read_to_string(path).map_err(|e| format!("Failed to read JWKS file: {}", e))?;
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse local JWKS: {}", e))?
        } else {
            let parsed_url = reqwest::Url::parse(&self.jwks_url).map_err(|e| format!("Invalid JWKS URL: {}", e))?;
            if parsed_url.scheme() == "http" {
                let is_localhost = matches!(
                    parsed_url.host_str(),
                    Some("localhost") | Some("127.0.0.1") | Some("::1")
                );
                let allow_insecure = std::env::var("HOLONOMY_ALLOW_INSECURE_JWKS")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false);
                
                if !is_localhost && !allow_insecure {
                    return Err("Insecure JWKS fetching is blocked. Use HTTPS or set HOLONOMY_ALLOW_INSECURE_JWKS=true for development.".to_string());
                }
            } else if parsed_url.scheme() != "https" {
                return Err(format!("Unsupported JWKS URL scheme: {}", parsed_url.scheme()));
            }

            self.client
                .get(&self.jwks_url)
                .send()
                .await
                .map_err(|e| format!("Failed to fetch JWKS: {}", e))?
                .json()
                .await
                .map_err(|e| format!("Failed to parse JWKS: {}", e))?
        };

        let mut cache = self.jwks_cache.write().await;
        for key in jwks.keys {
            cache.insert(key.kid.clone(), key);
        }
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> Result<UserContext, String> {
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;
        let kid = header
            .kid
            .ok_or_else(|| "JWT header missing 'kid'".to_string())?;

        // Check cache first
        let mut jwk_opt = {
            let cache = self.jwks_cache.read().await;
            cache.get(&kid).cloned()
        };

        // If not found, fetch JWKS and check again
        if jwk_opt.is_none() {
            self.fetch_jwks().await?;
            let cache = self.jwks_cache.read().await;
            jwk_opt = cache.get(&kid).cloned();
        }

        let jwk = jwk_opt.ok_or_else(|| format!("Key ID {} not found in JWKS", kid))?;

        if jwk.kty != "RSA" {
            return Err("Only RSA keys are supported".to_string());
        }

        let n = jwk
            .n
            .as_ref()
            .ok_or_else(|| "JWK missing 'n'".to_string())?;
        let e = jwk
            .e
            .as_ref()
            .ok_or_else(|| "JWK missing 'e'".to_string())?;

        let decoding_key = DecodingKey::from_rsa_components(n, e)
            .map_err(|err| format!("Failed to build decoding key: {}", err))?;

        // Support both RS256 and whatever is specified in the JWK if needed. Default to RS256
        let alg = match jwk.alg.as_deref() {
            Some("RS384") => Algorithm::RS384,
            Some("RS512") => Algorithm::RS512,
            _ => Algorithm::RS256,
        };

        let mut validation = Validation::new(alg);
        if !self.audience.is_empty() {
            validation.set_audience(&[&self.audience]);
        } else {
            validation.validate_aud = false;
        }
        validation.set_issuer(&[&self.issuer]);

        let token_data = decode::<UserContext>(token, &decoding_key, &validation)
            .map_err(|err| format!("JWT validation failed: {}", err))?;

        Ok(token_data.claims)
    }
}
