use holonomy_core::linter::validator::DataContract;
use holonomy_core::manager::policy_manager::{PolicyError, PolicyManager, PolicyProvider};
use holonomy_core::policy::manifest::{EncryptionBlock, PolicyLevel, PolicyManifest};
use std::sync::Arc;

struct MockPolicyProvider;
impl PolicyProvider for MockPolicyProvider {
    fn discover_policies(&self, _target: &str) -> Result<Vec<(PolicyLevel, String)>, PolicyError> {
        Ok(vec![])
    }
}

// @trace TASK-071
#[test]
fn test_semantic_tag_resolution() {
    let provider = Arc::new(MockPolicyProvider);
    let manager = PolicyManager::new_dangerously_allow_unsigned(provider);

    let contract_json = r#"{
        "name": "EmployeeData",
        "version": "1.0",
        "columns": [
            {
                "name": "employee_id",
                "type": "int32",
                "required": true
            },
            {
                "name": "social_security",
                "type": "string",
                "required": true,
                "tags": ["PII.ssn"]
            },
            {
                "name": "public_bio",
                "type": "string",
                "required": false,
                "tags": ["public"]
            },
            {
                "name": "health_record",
                "type": "string",
                "required": false,
                "tags": ["PHI.medical"]
            },
            {
                "name": "credit_card",
                "type": "string",
                "required": false
            },
            {
                "name": "my_secret_code",
                "type": "string",
                "required": false
            }
        ]
    }"#;

    let contract: DataContract = serde_json::from_str(contract_json).unwrap();
    let policy = PolicyManifest {
        version: "1.0".to_string(),
        principals: std::collections::HashMap::new(),
        encryption: Some(EncryptionBlock {
            required_tags: vec!["pii.ssn".to_string(), "phi.medical".to_string()],
            required_columns: vec!["credit_card".to_string(), "secret".to_string()],
        }),
        purpose_bindings: None,
    };

    let cols_to_encrypt = manager.resolve_columns_to_encrypt(&contract, &policy);

    assert!(cols_to_encrypt.contains(&"social_security".to_string()));
    assert!(cols_to_encrypt.contains(&"health_record".to_string()));
    assert!(cols_to_encrypt.contains(&"credit_card".to_string())); // explicit column
    assert!(cols_to_encrypt.contains(&"my_secret_code".to_string())); // explicit column fallback via regex replacement
    assert!(!cols_to_encrypt.contains(&"employee_id".to_string())); // not sensitive
    assert!(!cols_to_encrypt.contains(&"public_bio".to_string())); // not sensitive
}
