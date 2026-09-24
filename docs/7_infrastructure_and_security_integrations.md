# 7. Infrastructure & Security Integrations

## 7.1. Key Management Systems (KMS)
Holonomy relies heavily on external Key Management Systems to perform the cryptographic "Envelope Unwrapping" of the Data Encryption Keys (DEKs). The core encryption logic is entirely agnostic to the provider, relying on extensible adapters located in `holonomy-core/src/adapters/`.

**Supported Adapters:**

- **AWS KMS**: Fully supported natively using standard AWS credential chains for unwrapping symmetric keys.
- **GCP KMS**: Fully supported natively using standard Application Default Credentials for unwrapping symmetric keys.
- **HashiCorp Vault**: Experimental. Ideal for on-premise or multi-cloud environments. Connects via Transit Secrets Engine endpoints. *Note: HashiCorp Vault integration currently requires passing the `VAULT_TOKEN` as a raw environment variable and does not follow the standard programmatic configuration cascade.*

### 7.1.1. Key Creation Guidelines & Nuances

Holonomy uses **Envelope Encryption**. This means Holonomy generates a random AES-256 Data Encryption Key (DEK) locally, uses the DEK to encrypt the Parquet data, and then asks your KMS to encrypt (wrap) that DEK. Because the DEK is a small, symmetric AES key, your KMS keys **must** be configured specifically for symmetric encryption.

**Crucial Key Nuances:**

* **Must be Symmetric:** You *cannot* use Asymmetric (RSA/ECC) keys. Asymmetric keys are for signing or encrypting tiny payloads directly, not for high-speed DEK wrapping.
* **AWS KMS:** When creating a key in AWS KMS, you must select **Symmetric** as the Key type and **Encrypt and decrypt** as the Key usage. (The default `SYMMETRIC_DEFAULT` spec is correct).
* **GCP Cloud KMS:** When creating a Key Ring and Key in GCP, the Purpose must be set to **Symmetric encrypt/decrypt**. You cannot use MAC or Asymmetric sign/decrypt keys.
* **HashiCorp Vault:** When creating a key in the Transit engine (e.g., `vault write -f transit/keys/my-key`), the default type (`aes256-gcm96`) works perfectly. Do not use types like `rsa-2048` or `ecdsa-p256`.
* **Hardware Security Modules (HSM):** HSM-backed symmetric keys are fully supported across all providers (e.g., AWS CloudHSM backend) as long as the KMS exposes them as standard symmetric endpoints.

## 7.2. Enterprise Cloud Authentication & OIDC

Holonomy implements strict cryptographic OpenID Connect (OIDC) identity validation directly at the FFI boundary, ensuring absolute confidence in caller identity before any policies are evaluated.

### How to Configure Holonomy Authentication in Production

To make Holonomy work securely across your organization, follow these three clear steps:

#### Step 1: Infrastructure Team Configures the IdP
Your infrastructure or security team must first configure your Identity Provider (e.g., Keycloak, Azure Entra, Auth0, Okta) to support both human analysts and machine workloads:

1. **Create an OIDC Client:** Create a new client application for Holonomy in your IdP (e.g. `Client ID: holonomy-cli`).
2. **Set as a Public Client:** Configure the client to be a **Public Client** (e.g., Client Authentication = Off). The Holonomy CLI is a native terminal application and cannot securely store a `client_secret`.
3. **Enable Device Authorization Grant:** You **must explicitly enable** the OAuth 2.0 Device Authorization Grant (RFC 8628). This allows developers to authenticate via their browser on any device and have the token beamed back to their CLI.
4. **Define Audience (Optional but Recommended):** Define a custom audience (e.g., `api://holonomy-prod`) to prevent token reuse attacks.
5. **Require PKCE (Optional but Supported):** The Holonomy CLI natively implements PKCE (Proof Key for Code Exchange). You can safely leave "Require PKCE" enabled for this public client; the CLI will automatically generate and send the `code_challenge` and `code_verifier` during the device flow.

#### Step 1b: Granting Access & Writing Policies (Principal Mapping)
Once the IdP is configured, the Security/Access team must grant the user the appropriate permissions in the IdP, and the Data Owner must write a Holonomy Policy (`.holonomy_contract.json`) that matches those permissions.

Holonomy evaluates access by extracting strings from the JWT and flattening them into a single unified list of **"Principals"**. It automatically supports multiple major IdPs by extracting from all of the following JWT claims:

*   `sub` (The unique User ID)
*   `client_id` (The Machine/Service Account ID)
*   `groups` (Standard groups used by Okta, Azure Entra Groups, etc.)
*   `roles` (Standard roles used by Azure Entra App Roles, Okta custom claims, etc.)
*   `realm_access.roles` (The default role structure used by **Keycloak**)

**How it works in practice:**

1. **In the IdP:** The Security team assigns a user to a specific Group or Role (e.g., assigning a user the Keycloak Realm Role `"data-scientist"`, or an Entra Group `"data-scientist"`). 
2. **In the JWT:** When the user authenticates, the JWT will contain that string in one of the claims above (e.g., `"realm_access": {"roles": ["data-scientist"]}`).
3. **In the Policy:** The Data Owner must use that exact string as the key in the `principals` block of the policy:
```json
{
  "principals": {
    "data-scientist": {
      "allowed_columns": ["id", "email"]
    },
    "specific-user-uuid-1234": { 
      "allowed_columns": ["*"] 
    }
}
}
```
If the user's JWT contains `"data-scientist"` in *any* of the supported claims, Holonomy will match it to the `"data-scientist"` block in the policy and grant them the defined access!

#### Step 1c: Providing IdP Coordinates to Holonomy
Holonomy needs to know where your IdP is located so it can fetch the public keys to validate the JWT's signature (`jwks_url`) and initiate the CLI Device Login (`issuer`, `client_id`). 

Holonomy uses a powerful hierarchical configuration resolver. You can provide these settings in any of the following locations (highest priority first):

1. **Environment Variables** (Ideal for CI/CD and Docker containers)
2. **Project-level TOML** (`.holonomy.toml` in your project root or any parent directory)
3. **User-level TOML** (`~/.config/holonomy/config.toml` or `$XDG_CONFIG_HOME/holonomy/config.toml`)
4. **System-level TOML** (`/etc/holonomy/config.toml`)

**Example TOML Configuration:**
If you are using a `.holonomy.toml` file, configure the `[auth]` block like this:
```toml
[auth]
# Required for CLI login and cryptographically verifying the JWT
issuer = "http://localhost:8080/realms/master"
jwks_url = "http://localhost:8080/realms/master/protocol/openid-connect/certs"

# This must exactly match the Client ID you created in Step 1!
# If you named it "holonomy-app" in Keycloak/Okta, change this to "holonomy-app"
client_id = "holonomy-cli"

# Optional: Enforce a strict Audience to prevent token reuse
# audience = "api://holonomy-prod"
```

**Example Environment Variables (.env or export):**
```bash
export HOLONOMY_ISSUER="http://localhost:8080/realms/master"
export HOLONOMY_JWKS_URL="http://localhost:8080/realms/master/protocol/openid-connect/certs"
export HOLONOMY_CLIENT_ID="holonomy-cli"
# export HOLONOMY_AUDIENCE="api://holonomy-prod"
```

#### Step 2a: Human Analysts Authenticate via CLI
Data Scientists and Analysts do not need to manage tokens manually. They simply use the Holonomy CLI:

1. The analyst runs `holonomy auth login` in their terminal.
2. The CLI initiates the Device Authorization Grant and opens their web browser.
3. The analyst logs in via the IdP (supporting SSO, MFA, etc.).
4. The CLI automatically receives the JWT and securely stores it in `~/.holonomy/credentials`.
5. When the analyst runs their Python/DuckDB scripts, the Holonomy SDK automatically detects and uses this cached token!

#### Step 2b: CI/CD & Servers Authenticate via Environment
For headless environments (Kubernetes, Airflow, GitHub Actions), Holonomy operates as an "Identity Consumer". It natively ingests enterprise JWTs without custom auth libraries:

1. **Service Accounts (Dynamic Rotation):** For long-running pipelines in Kubernetes or Cloud Run, set the `HOLONOMY_CREDENTIAL_FILE` environment variable to point to your dynamically mounted Identity Token (e.g., `/var/run/secrets/kubernetes.io/serviceaccount/token`). Holonomy natively re-reads this file on every operation, seamlessly handling automatic infrastructure token rotations with zero downtime.
2. **Edge Devices & Static Environments:** For simpler setups, you can directly pass the raw token string via the `HOLONOMY_JWT` environment variable.

*Note: Holonomy automatically checks standard Cloud/Kubernetes paths before giving up. The exact resolution order is:*

1. `HOLONOMY_CREDENTIAL_FILE` (Explicit override)
2. `HOLONOMY_JWT` (Explicit override)
3. `AWS_WEB_IDENTITY_TOKEN_FILE` (AWS EKS / IAM)
4. `AZURE_FEDERATED_TOKEN_FILE` (Azure AKS / Workload Identity)
5. `/var/run/secrets/kubernetes.io/serviceaccount/token` (Kubernetes)
6. `~/.holonomy/credentials` (CLI Auth Login)


### Audience Enforcement (`aud`)
If your Infra team configured an Audience in Step 1, enforce it by setting `HOLONOMY_AUDIENCE=api://holonomy-prod`. Holonomy will strictly validate the `aud` claim. For internal tools where this is too restrictive, you can safely leave `HOLONOMY_AUDIENCE` unset; Holonomy will still cryptographically verify the RSA signature and Issuer.

## 7.3. Audit Trails & Telemetry
Every cryptographic action (e.g., DEK unwrap request, Policy rejection, Successful decryption) generates a security event.

To ensure analytics performance is never blocked by security logging, Holonomy uses the `AuditRingBuffer` and `Broadcaster` modules.

- Events are pushed onto an asynchronous, non-blocking lock-free ring buffer.
- A dedicated background thread drains this buffer and flushes the events via UDP/HTTPS to your centralized governance dashboard (e.g., Datadog, Splunk) outside the critical data path.

## 7.4. Applying Commercial Licenses

Holonomy uses a cascade resolution system to discover and apply commercial license keys. The engine will check the following locations in order, stopping at the first valid license it finds:

1. **Environment Variable:** The easiest way for CI/CD or Docker environments. Set `HOLONOMY_LICENSE_KEY` to the JSON payload of your license envelope.
   ```bash
   export HOLONOMY_LICENSE_KEY='{"signature": "...", "payload": "..."}'
   ```

2. **Configuration File (TOML):** You can provide the license key via any of the standard 6-tier configuration TOML files (e.g., `.holonomy.toml`, `~/.config/holonomy/config.toml`, `/etc/holonomy/config.toml`).
   ```toml
   [license]
   key = '''{"signature": "...", "payload": "..."}'''
   ```

3. **Programmatic Override (Python SDK):** If you are wrapping Holonomy in your own application, you can pass the license key directly during initialization.
   ```python
   import holonomy
   holonomy.init(license='{"signature": "...", "payload": "..."}')
   ```

4. **S3 Central Policy Bucket Fallback:** If no license is found locally, Holonomy will automatically attempt to download a file named `holonomy.lic` from the root of your configured central policy bucket (`policy.central_bucket`). This allows you to deploy a license to your entire organization centrally without updating individual developer workstations.
