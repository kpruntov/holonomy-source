# Policy Authoring Guide

The Holonomy Governance Engine relies on cryptographically signed Policy Manifests (`holonomy_master_policy.json`). This document describes the schema expected by the `PolicyManager`.

## What is a Policy Manifest?

A **Policy Manifest** governs **who** can access the data and **how** that data should be masked or filtered for specific users. It is evaluated at read-time (and write-time for encryption assertions).

Unlike a Data Contract (which defines the structural shape and assigns Semantic Tags to columns), a Policy defines the **Role-Based Access Control (RBAC)** rules. It maps Enterprise Identity Provider (IdP) roles/groups directly to row-level filters and column-level masking strategies (which can target the semantic tags assigned by the contract).

## The `PolicyManifest` Object

The root object describes the access rules for a specific domain or the global environment.

| Field | Type | Description |
|---|---|---|
| `version` | String | Semantic version of the policy. |
| `principals` | Object (Map) | A map where the key is the Principal string (e.g., `"data-scientist"`) and the value is a `PrincipalPolicy`. (Can also be aliased as `roles` in JSON). |
| `encryption` | Object (Optional) | Defines mandatory encryption constraints (see `EncryptionBlock`). |
| `purpose_bindings` | Object (Map) | Maps specific business "purposes" to IdP Roles for runtime disambiguation. |

## The `PrincipalPolicy` Object

Defines the exact permissions for a specific Principal (IdP Group, Role, or User Hash). When a user's JWT contains this Principal string in their `sub`, `groups`, or `roles` claim, these rules are applied.

| Field | Type | Description |
|---|---|---|
| `global_row_filters` | Array of Strings | SQL-like predicates that are **STRICTLY ENFORCED**. If the referenced column is missing from the dataset being read, the entire read operation is aborted with an `AccessDenied` error (Fail-Closed). |
| `selective_row_filters` | Array of Strings | SQL-like predicates that are **CONDITIONALLY ENFORCED**. If the dataset contains the referenced column, the filter is applied. If the column is missing, the filter is safely ignored (Fail-Open). |
| `column_masks` | Object (Map) | Maps exact physical column names to a masking strategy. (See **Allowed Masking Strategies** below). |
| `tag_masks` | Object (Map) | Maps Semantic Tags to a masking strategy. Any column carrying this tag in the Contract will automatically inherit this mask. |
| `sampling_cap` | Integer (Optional) | Hard limit on the number of rows this principal can read. |

### Allowed Masking Strategies
When defining a mask in `column_masks` or `tag_masks`, Holonomy supports exactly three string values:
1. `"PLAINTEXT"`: Explicitly allows the principal to read the raw, unmasked data.
2. `"REDACT"`: Replaces string values with `"***"`. For all other data types (integers, floats, dates), the entire column is nullified.
3. `"HASH"`: Computes a deterministic SHA-256 hex digest of string values. Useful for join keys. (Note: Non-string columns are currently returned untouched if HASH is applied to them).

## The `EncryptionBlock` Object

Defines what data MUST be encrypted at rest. The Write Orchestrator will reject any write that does not encrypt these assets.

| Field | Type | Description |
|---|---|---|
| `required_tags` | Array of Strings | Any column in the Data Contract possessing one of these tags MUST be encrypted (e.g., `["pii"]`). |
| `required_columns` | Array of Strings | Explicit physical columns that MUST be encrypted (e.g., `["ssn"]`). |

## Example Policy Manifest (JSON)

Note: When distributed, this JSON payload is wrapped inside a `PolicyEnvelope` containing the Ed25519 signature. Below is the raw `payload` structure:

```json
{
  "version": "1.0",
  "purpose_bindings": {
    "data-science-analytics": "data-scientist"
  },
  "encryption": {
    "required_tags": ["pii"],
    "required_columns": ["salary"]
  },
  "principals": {
    "data-scientist": {
      "global_row_filters": ["department = 'HR'"],
      "selective_row_filters": [],
      "column_masks": {
        "salary": "PLAINTEXT"
      },
      "tag_masks": {
        "pii": "REDACT"
      },
      "sampling_cap": 1000
    },
    "admin": {
      "global_row_filters": [],
      "selective_row_filters": [],
      "column_masks": {},
      "tag_masks": {}
    }
  }
}
```

## Purpose Bindings and Role Disambiguation

When a user authenticates (e.g., via JWT), they might belong to multiple roles simultaneously (e.g., `data-scientist` and `marketing`). To apply the correct access control rules, the `GovernanceManager` needs to know which role the user is acting under for a specific query.

The `purpose_bindings` map solves this by explicitly linking business "purposes" to specific roles. For example:
```json
{
  "purpose_bindings": {
    "data-science-analytics": "data-scientist",
    "marketing-campaign": "marketing"
  }
}
```
When a user executes a query with `purpose="data-science-analytics"`, the engine looks up the `purpose_bindings`, identifies the `data-scientist` role, and applies those specific row/column masking rules. If a user possesses multiple roles and no valid purpose (or `assumed_role`) is provided to disambiguate, the query is rejected.
