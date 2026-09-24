// @trace TASK-013
// @trace TASK-014
// @trace TASK-027
// @trace TASK-029
// @trace TASK-030
// @trace TASK-063
// @trace TASK-091
//! # Holonomy Core
//!
//! Holonomy is a data governance layer that handles cryptographic handshakes,
//! zero-copy memory transfers (Arrow), and policy enforcement (Parquet).
//!
//! ## Example
//!
//! ```
//! use holonomy_core::config::{Configuration, KmsConfig};
//! use holonomy_core::config::resolver::init_overrides;
//!
//! let config = Configuration {
//!     kms: Some(KmsConfig {
//!         provider: Some("aws".to_string()),
//!         endpoint: Some("https://kms.eu-west-1.amazonaws.com".to_string()),
//!         key_id: Some("alias/holonomy".to_string()),
//!         region: Some("eu-west-1".to_string()),
//!     }),
//!     policy: None,
//!     auth: None,
//!     telemetry: None,
//!     storage: None,
//!     license: None,
//! };
//!
//! // Initialize the global configuration singleton
//! init_overrides(config).expect("Failed to initialize config");
//!
//! // Engine is now ready to resolve DEKs and enforce policies
//! ```

pub mod adapters;
pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod governance;
pub mod ingestion;
pub mod linter;
pub mod manager;
pub mod policy;
pub mod schema;
