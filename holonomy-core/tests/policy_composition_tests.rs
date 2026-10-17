// @trace TASK-114
// @trace TASK-065
mod common;
use common::MockPolicyProvider;
// @trace TASK-035
use holonomy_core::manager::policy_manager::PolicyManager;
use holonomy_core::policy::manifest::PolicyLevel;

#[test]
fn test_policy_composition_precedence() {
    let global_manifest = r#"{
        "version": "1.0",
        "signature": "global_sig",
        "roles": {
            "analyst": {
                "column_masks": {
                    "ssn": "HASH"
                },
                "tag_masks": {
                    "pii": "REDACT",
                    "sensitive": "HASH"
                }
            }
        }
    }"#;

    let domain_manifest = r#"{
        "version": "1.0",
        "signature": "domain_sig",
        "roles": {
            "analyst": {
                "column_masks": {
                    "email": "NULL"
                },
                "tag_masks": {
                    "pii": "NULL",
                    "pci": "HASH"
                }
            }
        }
    }"#;

    let local_manifest = r#"{
        "version": "1.0",
        "signature": "local_sig",
        "roles": {
            "analyst": {
                "column_masks": {
                    "ssn": "PLAINTEXT"
                },
                "tag_masks": {
                    "pii": "PLAINTEXT",
                    "phi": "REDACT"
                }
            }
        }
    }"#;

    let policies = vec![
        (
            PolicyLevel::Local,
            serde_json::to_string(&serde_json::json!({
                "signature": "local_sig",
                "payload": local_manifest
            }))
            .unwrap(),
        ),
        (
            PolicyLevel::Domain,
            serde_json::to_string(&serde_json::json!({
                "signature": "domain_sig",
                "payload": domain_manifest
            }))
            .unwrap(),
        ),
        (
            PolicyLevel::Global,
            serde_json::to_string(&serde_json::json!({
                "signature": "global_sig",
                "payload": global_manifest
            }))
            .unwrap(),
        ),
    ];

    let manager =
        PolicyManager::new_dangerously_allow_unsigned(std::sync::Arc::new(MockPolicyProvider));
    let merged = manager.merge_layers(&policies).expect("Merging failed");

    let analyst_role = merged
        .principals
        .get("analyst")
        .expect("Missing analyst role");

    // SSN should be HASH (Global wins over Local)
    assert_eq!(analyst_role.column_masks.get("ssn").unwrap(), "HASH");

    // Email should be NULL (Domain wins as it's the only one defining it)
    assert_eq!(analyst_role.column_masks.get("email").unwrap(), "NULL");

    // PII tag mask should be REDACT (Global wins over Domain and Local)
    assert_eq!(analyst_role.tag_masks.get("pii").unwrap(), "REDACT");

    // PCI tag mask should be HASH (Domain wins over Local)
    assert_eq!(analyst_role.tag_masks.get("pci").unwrap(), "HASH");

    // PHI tag mask should be REDACT (Local wins as it's the only one defining it)
    assert_eq!(analyst_role.tag_masks.get("phi").unwrap(), "REDACT");
}
