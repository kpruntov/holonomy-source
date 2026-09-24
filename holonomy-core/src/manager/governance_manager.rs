// @trace TASK-078
// @trace TASK-013
// @trace TASK-066
// @trace FR-031
// @trace ADR-010
// @trace LCOMP-004
// @trace TASK-101
use crate::auth::jwt_validator::UserContext;
use crate::policy::manifest::PolicyManifest;
use arrow::array::Array;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum GovernanceError {
    #[error("Access Denied: {0}")]
    AccessDenied(String),
    #[error("Data Leak Prevented: {0}")]
    DataLeakPrevented(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailClosedMode {
    StrictError,
    #[default]
    GracefulMasking,
}

pub trait SchemaRegistryProvider: Send + Sync {
    fn resolve_contract(&self, target: &str) -> Option<String>;
}

#[derive(Clone)]
pub struct GovernanceManager {
    schema_provider: Arc<dyn SchemaRegistryProvider>,
}

impl GovernanceManager {
    pub fn new(schema_provider: Arc<dyn SchemaRegistryProvider>) -> Self {
        Self { schema_provider }
    }

    // @trace TASK-057
    pub fn resolve_contract(&self, target: &str) -> Option<String> {
        self.schema_provider.resolve_contract(target)
    }

    pub fn resolve_active_role<'a>(
        user_ctx: &'a UserContext,
        policy: &'a PolicyManifest,
        assumed_role: Option<&'a str>,
        purpose: Option<&'a str>,
    ) -> Result<&'a str, GovernanceError> {
        let purpose_bound_role = if let Some(p) = purpose {
            policy
                .purpose_bindings
                .as_ref()
                .and_then(|pb| pb.get(p).map(|s| s.as_str()))
        } else {
            None
        };

        if let (Some(bound), Some(assumed)) = (purpose_bound_role, assumed_role)
            && bound != assumed
        {
            return Err(GovernanceError::AccessDenied(format!(
                "Conflict: Purpose is bound to role '{}' but user assumed role '{}'",
                bound, assumed
            )));
        }

        let target_role = purpose_bound_role.or(assumed_role);

        if let Some(role) = target_role {
            if user_ctx.principals.contains(&role.to_string()) {
                return Ok(role);
            } else {
                return Err(GovernanceError::AccessDenied(format!(
                    "User does not possess the required/assumed role '{}'",
                    role
                )));
            }
        }

        let matching_roles: Vec<&String> = user_ctx
            .principals
            .iter()
            .filter(|p| policy.principals.contains_key(*p))
            .collect();

        if matching_roles.len() == 1 {
            Ok(matching_roles[0].as_str())
        } else if matching_roles.is_empty() {
            Err(GovernanceError::AccessDenied(
                "User has no roles that match any roles defined in the policy".to_string(),
            ))
        } else {
            Err(GovernanceError::AccessDenied(
                "User has multiple roles matching the policy. Must explicitly provide an assumed_role, or provide a purpose that is mapped to a specific role in the policy's purpose_bindings.".to_string(),
            ))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_rls(
        &self,
        array: std::sync::Arc<dyn arrow::array::Array>,
        user_ctx: &UserContext,
        policy: &PolicyManifest,
        column_name: &str,
        assumed_role: Option<&str>,
        purpose: Option<&str>,
        fail_closed_mode: Option<FailClosedMode>,
        is_physically_encrypted: bool,
        tags: &[String],
    ) -> Result<std::sync::Arc<dyn arrow::array::Array>, GovernanceError> {
        let mode = fail_closed_mode.unwrap_or_default();
        // LF-007: SIMD RLS & Masking
        // @trace TASK-104
        // @trace TASK-097
        // @trace TASK-012
        let padded_col = format!("_{}_", column_name.to_lowercase());
        let is_policy_encrypted_by_col = policy.encryption.as_ref().is_some_and(|enc| {
            enc.required_columns.iter().any(|c| {
                let padded_key = format!("_{}_", c.to_lowercase());
                padded_col.contains(&padded_key)
            })
        });

        let is_policy_encrypted_by_tag = policy
            .encryption
            .as_ref()
            .is_some_and(|enc| enc.required_tags.iter().any(|t| tags.contains(t)));

        let is_policy_encrypted = is_policy_encrypted_by_col || is_policy_encrypted_by_tag;

        if !is_physically_encrypted && is_policy_encrypted {
            return Err(GovernanceError::DataLeakPrevented(format!(
                "Column {} requires encryption by policy but was found in plaintext in the file",
                column_name
            )));
        }

        if !is_physically_encrypted {
            return Ok(array); // Permissive read for public columns
        }

        let active_role = Self::resolve_active_role(user_ctx, policy, assumed_role, purpose)?;

        if !policy.principals.contains_key(active_role) {
            return Err(GovernanceError::AccessDenied(format!(
                "Role '{}' not found in policy",
                active_role
            )));
        }

        let mut masks = std::collections::HashSet::new();

        if let Some(role_policy) = policy.principals.get(active_role) {
            let mut mask_found = false;
            for (key, mask) in &role_policy.column_masks {
                let padded_key = format!("_{}_", key.to_lowercase());
                if padded_col.contains(&padded_key) {
                    masks.insert(mask.clone());
                    mask_found = true;
                }
            }
            for tag in tags {
                if let Some(mask) = role_policy.tag_masks.get(tag) {
                    masks.insert(mask.clone());
                    mask_found = true;
                }
            }
            if !mask_found {
                masks.insert("UNLISTED".to_string());
            }
        }

        if masks.contains("PLAINTEXT") {
            return Ok(array);
        }

        let mut target_mask = if masks.contains("HASH") {
            "HASH".to_string()
        } else if masks.contains("REDACT") {
            "REDACT".to_string()
        } else if masks.contains("UNLISTED") {
            "UNLISTED".to_string()
        } else {
            let mut sorted: Vec<_> = masks.into_iter().collect();
            sorted.sort();
            sorted.pop().unwrap_or_else(|| "UNLISTED".to_string())
        };

        if target_mask == "UNLISTED" {
            match mode {
                FailClosedMode::StrictError => {
                    return Err(GovernanceError::AccessDenied(format!(
                        "Column '{}' is unlisted and strict fail-closed mode is active",
                        column_name
                    )));
                }
                FailClosedMode::GracefulMasking => {
                    target_mask = "REDACT".to_string();
                }
            }
        }

        if target_mask == "REDACT" {
            if let Some(sa) = array.as_any().downcast_ref::<arrow::array::StringArray>() {
                let mut builder = arrow::array::StringBuilder::new();
                for i in 0..sa.len() {
                    if sa.is_null(i) {
                        builder.append_null();
                    } else {
                        builder.append_value("***");
                    }
                }
                return Ok(std::sync::Arc::new(builder.finish()));
            } else if let Some(sa) = array
                .as_any()
                .downcast_ref::<arrow::array::LargeStringArray>()
            {
                let mut builder = arrow::array::LargeStringBuilder::new();
                for i in 0..sa.len() {
                    if sa.is_null(i) {
                        builder.append_null();
                    } else {
                        builder.append_value("***");
                    }
                }
                return Ok(std::sync::Arc::new(builder.finish()));
            } else {
                return Ok(Arc::new(arrow::array::new_null_array(
                    array.data_type(),
                    array.len(),
                )));
            }
        } else if target_mask == "HASH" {
            if let Some(sa) = array.as_any().downcast_ref::<arrow::array::StringArray>() {
                use sha2::{Digest, Sha256};
                let mut builder = arrow::array::StringBuilder::new();
                for i in 0..sa.len() {
                    if sa.is_null(i) {
                        builder.append_null();
                    } else {
                        let val = sa.value(i);
                        let hash = hex::encode(Sha256::digest(val.as_bytes()));
                        builder.append_value(hash);
                    }
                }
                return Ok(std::sync::Arc::new(builder.finish()));
            } else if let Some(sa) = array
                .as_any()
                .downcast_ref::<arrow::array::LargeStringArray>()
            {
                use sha2::{Digest, Sha256};
                let mut builder = arrow::array::LargeStringBuilder::new();
                for i in 0..sa.len() {
                    if sa.is_null(i) {
                        builder.append_null();
                    } else {
                        let val = sa.value(i);
                        let hash = hex::encode(Sha256::digest(val.as_bytes()));
                        builder.append_value(hash);
                    }
                }
                return Ok(std::sync::Arc::new(builder.finish()));
            } else {
                return Ok(Arc::new(arrow::array::new_null_array(
                    array.data_type(),
                    array.len(),
                )));
            }
        }

        Ok(array)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct MockSchemaRegistryProvider;
    impl SchemaRegistryProvider for MockSchemaRegistryProvider {
        fn resolve_contract(&self, _target: &str) -> Option<String> {
            None
        }
    }

    #[test]
    fn test_apply_rls_masking() {
        let manager = GovernanceManager::new(Arc::new(MockSchemaRegistryProvider));

        let mut policy = crate::policy::manifest::PolicyManifest {
            version: "1.0".to_string(),
            principals: std::collections::HashMap::new(),
            encryption: Some(crate::policy::manifest::EncryptionBlock {
                required_tags: vec!["phi".to_string()],
                required_columns: vec!["email".to_string(), "ssn".to_string()],
            }),
            purpose_bindings: None,
        };

        // Role A requires HASH for email
        let mut role_a = crate::policy::manifest::PrincipalPolicy::default();
        role_a
            .column_masks
            .insert("email".to_string(), "HASH".to_string());
        role_a
            .tag_masks
            .insert("pii".to_string(), "REDACT".to_string());
        policy.principals.insert("RoleA".to_string(), role_a);

        // Role B allows cleartext (PLAINTEXT)
        let mut role_b = crate::policy::manifest::PrincipalPolicy::default();
        role_b
            .column_masks
            .insert("email".to_string(), "PLAINTEXT".to_string());
        policy.principals.insert("RoleB".to_string(), role_b);

        // Role C requires REDACT for email
        let mut role_c = crate::policy::manifest::PrincipalPolicy::default();
        role_c
            .column_masks
            .insert("email".to_string(), "REDACT".to_string());
        policy.principals.insert("RoleC".to_string(), role_c);

        let email_array =
            std::sync::Arc::new(arrow::array::StringArray::from(vec!["test@test.com"]))
                as std::sync::Arc<dyn arrow::array::Array>;

        // Case 1: User has only RoleA -> Should be masked (HASH)
        let ctx1 = UserContext {
            sub: Some("user1".to_string()),
            client_id: None,
            email: None,
            principals: vec!["RoleA".to_string()],
            extra: std::collections::HashMap::new(),
        };
        let res1 = manager
            .apply_rls(
                email_array.clone(),
                &ctx1,
                &policy,
                "email",
                None,
                None,
                None,
                true,
                &[],
            )
            .unwrap();
        let str_res1 = res1
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        use sha2::{Digest, Sha256};
        let expected_hash = hex::encode(Sha256::digest(b"test@test.com"));
        assert_eq!(str_res1.value(0), expected_hash);

        // Case 2: User has RoleA and RoleB -> Should be error without assumed_role
        let ctx2 = UserContext {
            sub: Some("user2".to_string()),
            client_id: None,
            email: None,
            principals: vec!["RoleA".to_string(), "RoleB".to_string()],
            extra: std::collections::HashMap::new(),
        };
        let res2_err = manager.apply_rls(
            email_array.clone(),
            &ctx2,
            &policy,
            "email",
            None,
            None,
            None,
            true,
            &[],
        );
        assert!(res2_err.is_err());

        let res2 = manager
            .apply_rls(
                email_array.clone(),
                &ctx2,
                &policy,
                "email",
                Some("RoleB"),
                None,
                None,
                true,
                &[],
            )
            .unwrap();
        let str_res2 = res2
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(str_res2.value(0), "test@test.com");

        // Case 3: User has RoleA and RoleC -> Resolve to RoleC
        let ctx3 = UserContext {
            sub: Some("user3".to_string()),
            client_id: None,
            email: None,
            principals: vec!["RoleA".to_string(), "RoleC".to_string()],
            extra: std::collections::HashMap::new(),
        };
        let res3 = manager
            .apply_rls(
                email_array.clone(),
                &ctx3,
                &policy,
                "email",
                Some("RoleC"),
                None,
                None,
                true,
                &[],
            )
            .unwrap();
        let str_res3 = res3
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(str_res3.value(0), "***"); // REDACT

        // Case 4: Unrecognized group -> Access Denied (Fail-Open vulnerability fixed)
        let ctx4 = UserContext {
            sub: Some("user4".to_string()),
            client_id: None,
            email: None,
            principals: vec!["RoleUnknown".to_string()],
            extra: std::collections::HashMap::new(),
        };
        let res4 = manager.apply_rls(
            email_array.clone(),
            &ctx4,
            &policy,
            "email",
            None,
            None,
            None,
            true,
            &[],
        );
        assert!(matches!(res4, Err(GovernanceError::AccessDenied(_))));

        // Case 5: Unlisted encrypted column with StrictError -> Access Denied
        let res5 = manager.apply_rls(
            email_array.clone(),
            &ctx1,
            &policy,
            "ssn",
            None,
            None,
            Some(FailClosedMode::StrictError),
            true,
            &[],
        );
        assert!(matches!(res5, Err(GovernanceError::AccessDenied(_))));

        // Case 6: Unlisted encrypted column with GracefulMasking -> REDACT
        let res6 = manager
            .apply_rls(
                email_array.clone(),
                &ctx1,
                &policy,
                "ssn",
                None,
                None,
                Some(FailClosedMode::GracefulMasking),
                true,
                &[],
            )
            .unwrap();
        let str_res6 = res6
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(str_res6.value(0), "***");

        // Case 7: Hybrid Data Leak Prevention
        // Policy says "ssn" must be encrypted, but we pass is_physically_encrypted = false
        let res7 = manager.apply_rls(
            email_array.clone(),
            &ctx1,
            &policy,
            "ssn",
            None,
            None,
            None,
            false,
            &[],
        );
        assert!(matches!(res7, Err(GovernanceError::DataLeakPrevented(_))));

        // Case 8: Semantic Tag Masking
        // Column is "username", which has no column_mask, but has tag "pii".
        // RoleA has a tag_mask for "pii" -> "REDACT".
        let username_array = std::sync::Arc::new(arrow::array::StringArray::from(vec!["test_user"]))
            as std::sync::Arc<dyn arrow::array::Array>;
        let res8 = manager
            .apply_rls(
                username_array.clone(),
                &ctx1,
                &policy,
                "username",
                None,
                None,
                None,
                true,
                &["pii".to_string()],
            )
            .unwrap();
        let str_res8 = res8
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap();
        assert_eq!(str_res8.value(0), "***");

        // Case 9: Tag-Based Data Leak Prevention (DLP)
        // Column is "health_status", not in required_columns, but has tag "phi".
        // "phi" is in required_tags, so it must be encrypted. We pass is_physically_encrypted = false.
        let health_array = std::sync::Arc::new(arrow::array::StringArray::from(vec!["healthy"]))
            as std::sync::Arc<dyn arrow::array::Array>;
        let res9 = manager.apply_rls(
            health_array.clone(),
            &ctx1,
            &policy,
            "health_status",
            None,
            None,
            None,
            false,
            &["phi".to_string()],
        );
        assert!(matches!(res9, Err(GovernanceError::DataLeakPrevented(_))));
    }
}
