// @trace TASK-114
// @trace TASK-035
// @trace TASK-041
// @trace TASK-079
// @trace TASK-097
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyLevel {
    Local = 0,
    Domain = 1,
    Global = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyEnvelope {
    pub signature: String,
    pub payload: String, // raw JSON string of the PolicyManifest
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyManifest {
    pub version: String,
    #[serde(default, alias = "roles")]
    pub principals: HashMap<String, PrincipalPolicy>,
    #[serde(default)]
    pub encryption: Option<EncryptionBlock>,
    #[serde(default)]
    pub purpose_bindings: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EncryptionBlock {
    #[serde(default)]
    pub required_tags: Vec<String>,
    #[serde(default)]
    pub required_columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PrincipalPolicy {
    #[serde(default)]
    pub global_row_filters: Vec<String>,
    #[serde(default)]
    pub selective_row_filters: Vec<String>,
    #[serde(default)]
    pub column_masks: HashMap<String, String>,
    #[serde(default)]
    pub tag_masks: HashMap<String, String>,
    pub sampling_cap: Option<u64>,
}

impl PolicyManifest {
    pub fn merge(mut self, other: Self) -> Self {
        // Merge Principals
        for (principal, other_principal_policy) in other.principals {
            let self_principal_policy = self.principals.entry(principal).or_default();

            // For row filters, we concatenate them so all restrictions apply
            self_principal_policy
                .global_row_filters
                .extend(other_principal_policy.global_row_filters);
            self_principal_policy
                .selective_row_filters
                .extend(other_principal_policy.selective_row_filters);

            // For column masks, higher precedence overrides
            for (col, mask) in other_principal_policy.column_masks {
                self_principal_policy.column_masks.insert(col, mask);
            }

            // For tag masks, higher precedence overrides
            for (tag, mask) in other_principal_policy.tag_masks {
                self_principal_policy.tag_masks.insert(tag, mask);
            }

            // For sampling cap, take the most restrictive (minimum) value
            self_principal_policy.sampling_cap = match (
                self_principal_policy.sampling_cap,
                other_principal_policy.sampling_cap,
            ) {
                (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
        }

        // Merge EncryptionBlock (union)
        if let Some(other_enc) = other.encryption {
            if let Some(ref mut self_enc) = self.encryption {
                for tag in other_enc.required_tags {
                    if !self_enc.required_tags.contains(&tag) {
                        self_enc.required_tags.push(tag);
                    }
                }
                for col in other_enc.required_columns {
                    if !self_enc.required_columns.contains(&col) {
                        self_enc.required_columns.push(col);
                    }
                }
            } else {
                self.encryption = Some(other_enc);
            }
        }

        // Merge purpose_bindings
        if let Some(other_pb) = other.purpose_bindings {
            if let Some(ref mut self_pb) = self.purpose_bindings {
                for (k, v) in other_pb {
                    self_pb.insert(k, v);
                }
            } else {
                self.purpose_bindings = Some(other_pb);
            }
        }

        self
    }
}
