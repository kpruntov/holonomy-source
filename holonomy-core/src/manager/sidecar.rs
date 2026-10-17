// @trace TASK-122
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarKeyEntry {
    pub purpose: String,
    pub column: String,
    pub wrapped_dek: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarMetadata {
    pub version: String,
    pub keys: Vec<SidecarKeyEntry>,
}

impl Default for SidecarMetadata {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            keys: Vec::new(),
        }
    }
}
