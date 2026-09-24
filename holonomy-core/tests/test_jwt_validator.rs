// @trace TASK-097
use holonomy_core::auth::jwt_validator::UserContext;

#[test]
fn test_user_context_principal_extraction() {
    let json_str = r#"{
        "sub": "user123",
        "client_id": "client_abc",
        "email": "test@example.com",
        "groups": ["group-A", "group-B"],
        "roles": ["role-X", "role-Y"],
        "realm_access": {
            "roles": ["realm-role-1", "realm-role-2"]
        },
        "extra_field": "some_value"
    }"#;

    let user_ctx: UserContext = serde_json::from_str(json_str).expect("Failed to deserialize");

    assert_eq!(user_ctx.sub, Some("user123".to_string()));

    let mut expected_principals = vec![
        "group-A".to_string(),
        "group-B".to_string(),
        "realm-role-1".to_string(),
        "realm-role-2".to_string(),
        "role-X".to_string(),
        "role-Y".to_string(),
        "user123".to_string(),
        "client_abc".to_string(),
    ];
    expected_principals.sort();

    assert_eq!(user_ctx.principals, expected_principals);
}

#[test]
fn test_user_context_partial_principals() {
    let json_str = r#"{
        "sub": "user123",
        "roles": ["role-Z"]
    }"#;

    let user_ctx: UserContext = serde_json::from_str(json_str).expect("Failed to deserialize");

    let mut expected_principals = vec!["role-Z".to_string(), "user123".to_string()];
    expected_principals.sort();

    assert_eq!(user_ctx.principals, expected_principals);
}

#[test]
fn test_user_context_empty_principals() {
    let json_str = r#"{
        "sub": "user123"
    }"#;
    let user_ctx: UserContext = serde_json::from_str(json_str).expect("Failed to deserialize");
    assert_eq!(user_ctx.principals, vec!["user123".to_string()]);
}
