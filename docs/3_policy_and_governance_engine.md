# 3. The Policy & Governance Engine

## 3.1. Policy Engine Configuration

The Policy & Governance Engine relies on several key configuration variables to locate and securely validate your enterprise data policies:

- **`policy_bucket` / `HOLONOMY_POLICY_BUCKET`**: The storage URI (e.g., `s3://my-bucket/policies`, `r2://...`) pointing to the centralized location of your signed `holonomy_master_policy.json`. If set to `"local"`, Holonomy reads local un-signed policies for development.
- **`public_key` / `HOLONOMY_PUBLIC_KEY`**: The Ed25519 public key used to cryptographically verify the digital signatures on your master policy manifest, ensuring it hasn't been tampered with.
- **`cache_ttl_hours` / `HOLONOMY_CACHE_TTL_HOURS`**: Dictates how long the policy engine is allowed to cache remote policy manifests in memory before requiring a fresh network pull (defaults to 24 hours).

**How these are resolved:**
Holonomy evaluates these variables via a deterministic **6-Tier Configuration Cascade**. It checks for values in a strict order of priority, starting from explicit programmatic overrides in code (`holonomy.init()`), down through environment variables (`HOLONOMY_*`), local project configuration files (`.holonomy.toml`), user/system TOML files, and finally falling back to hardcoded system defaults.

For an extended breakdown of the 6-tier cascade and where you should store specific variables across different deployment environments, please refer to:

- [2. Getting Started & Installation (Section 2.4)](2_getting_started_and_installation.md)
- [7. Infrastructure & Security Integrations](7_infrastructure_and_security_integrations.md)

## 3.2. Data Contracts vs. Policy Manifests

Holonomy decouples Data Engineering (Data Shape) from Data Governance (Data Access) by using two distinct declarative artifacts: **Data Contracts** and **Policy Manifests**.

1. **Data Contract (`.holonomy_contract.json`)**: Governs **WHAT** the data is. It defines the physical structure (column names, types, regex bounds) and assigns **Semantic Tags** (e.g., `"pii"`, `"finance"`) to specific physical columns. It is evaluated at *write-time*.
2. **Policy Manifest (`holonomy_master_policy.json`)**: Governs **WHO** can access the data and **HOW** they see it. It maps your Enterprise Identity Provider (IdP) groups to row-level filters and column-level masking strategies. It is evaluated at *read-time* (and used to assert encryption at *write-time*).

**The Relationship:** A Data Steward defines the Semantic Tags in the Data Contract. The Security team writes a Policy Manifest that applies a masking strategy to that tag (e.g., `{"pii": "REDACT"}`). This perfectly decouples security rules from physical database schemas!

## 3.3. Hierarchical Data Contract Resolution

Holonomy enforces strict edge-linting constraints for data writes by resolving Data Contracts hierarchically. (Note: the `target` being written to can be a remote URI like `s3://...` or a local file path like `file:///tmp/...`):

1. **Remote Schema Registry (`[target_base64].json`)**: Holonomy attempts to fetch the canonical schema contract from the remote metadata store based on the `target` URI.
2. **Local Fallback (`.holonomy_contract.json`)**: If no remote schema is registered, it looks for a hardcoded local `.holonomy_contract.json` file in the current working directory.
3. **Explicit Override**: Edge-linting constraints can be passed programmatically via the `contract_json` string argument in the `holonomy.write()` API.

*For detailed schema definitions on creating these files, see the [Contract Authoring Guide](contract_authoring.md).*

## 3.4. Centralized Policy Manifests

Holonomy prevents local configuration tampering through centralized, cryptographically signed policy manifests. 

Instead of trusting the local environment to decide who can access what, the `GovernanceManager` fetches the `holonomy_master_policy.json` (the Global Policy Manifest) from your centralized `policy_bucket` to enforce RBAC, Row-Level Security, and Data Masking.


*Example Policy Manifest Payload (Decoded)*:
```json
{
  "version": "1.0",
  "purpose_bindings": {
    "data-science-analytics": "data_scientist"
  },
  "encryption": {
    "required_tags": ["pii"],
    "required_columns": ["salary"]
  },
  "principals": {
    "data_scientist": {
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

*For detailed schema definitions on creating these files, see the [Policy Authoring Guide](policy_authoring.md).*

### Role Disambiguation (Purpose Bindings)
When a user authenticates via OIDC, their token may contain multiple groups (e.g., `data-scientist` and `marketing`). Because each role has different masking strategies, the `GovernanceManager` must resolve the ambiguity. 
The Policy Manifest includes a `purpose_bindings` mapping that links a business query "purpose" (like `data-science-analytics`) directly to a role (like `data-scientist`). When the analyst calls `holonomy.read(purpose="data-science-analytics")`, the engine automatically selects the `data-scientist` masking rules!

### Cryptographic Signatures
Policies must be signed by an authorized administrator (via `ed25519_dalek` elliptic curve signatures). If a malicious user attempts to modify their local copy of the policy to grant themselves access, the `PolicyManager::verify_signatures` routine will immediately reject the tampered policy and block all decryption attempts.

### Role-Based Access Control (RBAC) via IdP Groups
Policies map active roles (Principals) to data assets. The strings you define in your policy (like `"data_scientist"`) must exactly match the Groups or Roles returned in the user's JWT from your Enterprise IdP (e.g., Azure AD, Okta, Keycloak). When a user authenticates, Holonomy cross-references their IdP groups against this policy to dynamically enforce access.

## 3.4. Enterprise IdP Integration (JWT Validation)
Holonomy supports native integration with Enterprise Identity Providers (IdPs) like Okta, Azure AD, or Ping Identity.

Instead of passing opaque user identifiers to the read/write APIs, clients pass standard OIDC/OAuth JSON Web Tokens (JWTs). 

Holonomy cryptographically validates these JWTs by:

1. Fetching the IdP's JSON Web Key Set (JWKS) endpoint.
2. Locating the appropriate RSA public key via the `kid` header.
3. Verifying the token's RSA signature (`RS256`, `RS384`, `RS512`).
4. Checking the `aud` (Audience) and `exp` (Expiration) claims securely.
5. Extracting `sub`, `email`, and `groups` claims to construct the `UserContext` for deterministic Role-Based Access Control.

**Recommendation for Users:** Ensure your application always instantiates `JwtValidator` with the exact JWKS URI of your trusted IdP and your expected Audience string to prevent cross-service token replay attacks.
