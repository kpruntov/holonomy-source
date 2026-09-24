# 2. Getting Started & Installation

## 2.1. System Requirements
Holonomy is designed to run anywhere you can run Python, without requiring users to compile Rust code themselves. 

**Supported Operating Systems:**
- Linux (x86_64, aarch64)
- macOS (Intel, Apple Silicon / ARM64)
- Windows (AMD64)

**Supported Environments:**
- Python 3.8+ 
- Rust compilation toolchain is **not** required for end-users, as Holonomy is distributed via PyPI as pre-compiled `maturin` wheels.
- Dependencies: Requires `pyarrow` for in-memory FFI handoffs.

## 2.2. Installation Guide
Because Holonomy bundles its Rust-compiled `core` and its standalone `cli` directly into the Python wheel, installation is completely unified. 

**Using `pip`:**
```bash
pip install holonomy
```

**Using `uv` (Recommended for Speed):**
```bash
uv add holonomy
```

**Verifying the Installation:**
To ensure both the Python API and the bundled CLI are functional, run:
```bash
# Check the Python module
python -c "import holonomy; print('Holonomy successfully loaded')"

# Check the bundled CLI (automatically injected into your environment's bin folder)
holonomy --help
```

## 2.3. Zero-Config Local Dev Mode

If you simply install Holonomy and execute a script without configuring anything, the SDK automatically falls back to **Local Dev Mode**. It makes the following assumptions:
- **KMS Endpoint:** Defaults to an internal **Local Mock KMS** that encrypts/decrypts using a local RAM session key.
- **Policy Storage:** Defaults to checking the local `./.holonomy/policies/` directory. For a frictionless Developer Experience (DX), any raw YAML/JSON policies found here are automatically cryptographically signed in-memory using an ephemeral keypair during engine startup. This ensures the Engine's strict signature verification logic remains active and identical to production, while allowing you to simply write plain-text rules locally. If no policies exist, it permits local execution.
- **Audit Logs:** Defaults to writing events locally to `~/.holonomy/audit.log` instead of streaming them to a SaaS control plane.

This allows you to test Parquet Modular Encryption (PME) completely locally without needing AWS, HashiCorp Vault, or S3 credentials. Once you move to production, simply set environment variables (e.g., `HOLONOMY_KMS_ENDPOINT`) and the exact same code securely connects to your real infrastructure!

## 2.4. Configuration Reference & 6-Tier Cascade

When you are ready to configure Holonomy for a real environment, you can supply configuration via a **6-Tier Hierarchical Cascade**. This deterministic resolution matrix ensures that infrastructure variables are abstracted away from primary query execution paths, allowing your code to remain 100% portable across environments.

The configuration engine resolves parameters implicitly and exactly once. The exact resolution order is:
1. **Programmatic Overrides:** Arguments explicitly passed into `holonomy.init(...)`.
2. **Environment Variables:** Standard `HOLONOMY_*` environment variables (e.g., via standard shell exports or `.env` files).
3. **Project Config:** Reading from `./.holonomy.toml` in the current working directory.
4. **User Config:** Reading from `~/.config/holonomy/config.toml` (or the OS-specific user config directory).
5. **System Global Config:** Reading from `/etc/holonomy/config.toml` (or the OS-specific system config directory).
6. **System Fail-Safe Defaults:** Automatic fallbacks (e.g., `cache_ttl_hours = 24`).

### Where to Put Configuration vs. Credentials

It is vital to distinguish between **Configuration** (how Holonomy behaves) and **Credentials** (how Holonomy proves its identity to third-party services).

#### 1. Core Configuration (Engine Settings)
Variables such as your KMS endpoint, policy bucket URI, storage routing, telemetry target, and IdP definitions belong in the Holonomy configuration cascade. We recommend keeping these in `.holonomy.toml` or `HOLONOMY_*` environment variables.

*Example `.holonomy.toml` structure:*
```toml
[kms]
provider = "gcp" # Optional, defaults to auto-discovery
key_id = "projects/.../cryptoKeys/holonomy-kms-test1"

[storage]
endpoint = "https://<your-s3-endpoint>.com"
region = "auto"

[policy]
central_bucket = "r2://holonomy-test-policy-bucket"
public_key = "e67b56a920edf3d693d2a1884ecfcb4b7d1da89e123c7bbed97d53552b9428ec"

[auth]
jwks_url = "http://localhost:8080/realms/holonomy-test/protocol/openid-connect/certs"
issuer = "http://localhost:8080/realms/holonomy-test"
```

#### 2. Holonomy Authentication Credentials (JWT Identity)
For Holonomy to prove *your identity* during policy evaluation, it requires an OIDC/JWT token. This is resolved natively by the Holonomy config engine cascade via:
- `credential_file` config / `HOLONOMY_CREDENTIAL_FILE`: Path to a dynamically rotating token file (ideal for Kubernetes service accounts).
- Standard Fallbacks: If omitted, Holonomy searches standard identity paths like AWS/Azure Federated tokens or the local `~/.holonomy/credentials` file (which is automatically generated when you use the CLI command `holonomy auth login`).

#### 3. Third-Party Infrastructure Credentials (AWS/GCP/S3)
**Holonomy does NOT parse or store third-party infrastructure credentials (like `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `GOOGLE_APPLICATION_CREDENTIALS`) in its TOML files.**
Instead, Holonomy securely delegates infrastructure authentication directly to the native Cloud SDKs (e.g., `aws-config`, `gcp-auth`). 

- **Cloud Credentials MUST remain in standard environment variables (e.g., loaded via a `.env` file) or native OS config files (e.g., `~/.aws/credentials`).**
- Do NOT place cloud access keys into `.holonomy.toml`.

## 2.5. Quick-Start Tutorial

### Step 1: Initialization

By default, Holonomy securely initializes its context by looking for your environment's Identity Token (OIDC, AWS IAM, K8s Service Account) and uses standard configuration discovery. 

For this local development tutorial, we will explicitly configure it to use mock cryptographic keys and local policy files.

```python
import holonomy

# 1. Initialize your environment locally (explicit overrides)
holonomy.init(
    kms_provider="mock",
    policy_bucket="local",
    identity_provider="mock"
)
```

### Step 1.5: Defining a Local Governance Policy
Holonomy's core strength is its Decoupled Governance Engine. By default in Local Dev Mode (which we enabled above), Holonomy looks for JSON policies in a `.holonomy/policies/` directory relative to where your script is running. 

Let's create a local policy that tells Holonomy to automatically redact the `email` column for anyone acting as the `data-sci-role`. 

Create a file named `.holonomy/policies/demo_policy.json` in your project folder (you may need to create the directory first) and paste this in:
```json
{
  "version": "1.0",
  "encryption": {
    "required_columns": ["email"]
  },
  "principals": {
    "data-sci-role": {
      "column_masks": {
        "email": "REDACT"
      }
    }
  }
}
```
When you run the read operations in the later steps as `data-sci-role`, the engine will intercept the decrypted data and instantly replace the email addresses with `***` directly in memory!

### Step 2: Writing Protected Data
Let's encrypt and write a batch of sensitive data. We define an inline JSON contract ensuring structural integrity before the data ever leaves memory.
```python
import holonomy
import pyarrow as pa

# Create some dummy PyArrow data
schema = pa.schema([
    ('id', pa.int64()), 
    ('email', pa.string())
])
batch = pa.RecordBatch.from_arrays(
    [pa.array([1, 2]), pa.array(["user@test.com", "admin@test.com"])], 
    schema=schema
)

# 2. Write data with Parquet Modular Encryption (PME)
contract_json = '{"name": "Users", "version": "1.0", "columns": [{"name": "id", "type": "int64", "required": true}, {"name": "email", "type": "string", "required": true}]}'

holonomy.write(
    batch=batch, 
    target="file://users_encrypted.parquet",
    user_context="data-eng-role",
    purpose="business-analysis",
    contract_json=contract_json
)
```

### Step 3: Reading Protected Data (Zero-Copy)

First, let's prove the data is actually encrypted at rest. If you try to read the file using standard tools like Polars, it will fail or return ciphertext because it lacks the cryptographic keys:

```python
import polars as pl
try:
    df_raw = pl.read_parquet("users_encrypted.parquet")
    print(df_raw)
except Exception as e:
    print(f"Standard reader failed: {e}")
```

Now, let's load that data securely directly into a Polars DataFrame. Holonomy handles the local file reads and decryption seamlessly.
```python
import holonomy
import polars as pl

# 3. Read specific encrypted column directly into Arrow
arrow_data = holonomy.read(
    target="file://users_encrypted.parquet",
    user_context="data-sci-role",
    columns_to_read=["email"], 
    purpose="data-science-analytics"
)

# 4. Zero-Copy transition into Polars
df = pl.from_arrow(arrow_data)
print(df)
```

### Step 4: Lazy Scanning (Zero-Copy Stream)
For massive datasets where eager `read()` would exceed memory limits, you can use `holonomy.scan()` to retrieve a deferred `pyarrow.RecordBatchReader`. This stream natively integrates with DuckDB's lazy query engine and Polars, deferring execution and allowing memory-bounded reads.

**Option A: Ingesting into Polars**
Note that an Arrow stream is a one-pass iterator that can only be consumed once.
```python
import holonomy
import polars as pl

# 1. Open an encrypted stream via the Arrow C Stream interface
stream = holonomy.scan(
    target="file://users_encrypted.parquet",
    user_context="data-sci-role",
    columns_to_read=["id", "email"], 
    purpose="large-scale-analytics"
)

# 2. Consume the pre-filtered stream natively into Polars
df = pl.from_arrow(stream)
print(df)
```

**Option B: Querying robustly with DuckDB**
If you want to use DuckDB, you must open a fresh stream since the previous one was exhausted by Polars.
```python
import holonomy
import duckdb

stream2 = holonomy.scan(
    target="file://users_encrypted.parquet",
    user_context="data-sci-role",
    columns_to_read=["id", "email"], 
    purpose="large-scale-analytics"
)

# Using from_arrow prevents scope resolution issues in production ETLs
res = duckdb.from_arrow(stream2).query("my_table", "SELECT * FROM my_table").df()
print(res)
```

### Step 5: Predicate Pruning (Pushdown)
To minimize network egress and decryption time, you can push AST filters down into Holonomy's Rust core. 

> [!IMPORTANT]
> Holonomy uses these user filters *strictly* for block-level I/O pruning (skipping Parquet chunks where the `min`/`max` statistics don't overlap with your filter). It does **not** evaluate these filters row-by-row! You must still apply the exact filter in your compute engine (e.g. Polars) to remove any remaining invalid rows from the fetched chunks.

*(Note: If you run this on our dummy dataset of 2 rows, both rows are written into the exact same chunk, so the entire chunk is fetched and you will see both rows until Polars filters them out!)*

```python
import holonomy
import pyarrow.compute as pc
import polars as pl

# 1. Create a native PyArrow filter expression
filters = pc.field("id") == 1

# 2. Pass the filters to the scanner
# Holonomy translates this AST and bypasses downloading any Parquet 
# chunk where `id != 1` based on the chunk's footer statistics.
stream = holonomy.scan(
    target="file://users_encrypted.parquet",
    user_context="data-sci-role",
    columns_to_read=["id", "email"], 
    purpose="large-scale-analytics",
    filters=filters
)

# 3. Consume the stream and apply the EXACT row filter in Polars
df = pl.from_arrow(stream).filter(pl.col("id") == 1)
print(df)
```

## 2.6. Configuring your Identity Provider (IdP) for the CLI

If you intend to use the interactive `holonomy auth login` command (which implements the OAuth 2.0 Device Authorization Grant - RFC 8628), you must configure your IdP (e.g., Keycloak, Auth0, Okta) as follows:

1. **Client Type / Authentication:** Set the client to be a **Public Client** (e.g., Client Authentication = Off). The CLI cannot securely store a `client_secret`, so it relies strictly on public flows.
2. **Device Authorization Grant:** You **must explicitly enable** the OAuth 2.0 Device Authorization Grant. 
3. **URL Settings:** Because the CLI is a native terminal application and not a web server:
   - **Root URL / Home URL:** Leave blank.
   - **Valid Redirect URIs:** Leave blank (there is no redirect callback).
   - **Web Origins / CORS:** Leave blank.
4. **Logout Settings:** No Front-Channel or Back-Channel logout URLs are required. Logout is managed locally by deleting the credentials file.

Once configured, ensure `HOLONOMY_ISSUER` and `HOLONOMY_CLIENT_ID` are set in your environment (e.g. `.env` file) to match your IdP settings.
