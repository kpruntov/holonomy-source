# 4. The Producer Path: Secure Data Ingestion (Writing)

## 4.1. The `holonomy.write()` and `holonomy.Writer()` APIs
The producer path is responsible for accepting plaintext data from a Python process, validating it against security contracts, encrypting sensitive columns, and streaming it upstream. Holonomy provides two APIs for this depending on the size of your data.

*(Source of truth: [holonomy-py/python/holonomy/__init__.py](holonomy-py/python/holonomy/__init__.py))*

### `holonomy.write()` (Single Batch)
Use this for writing a single PyArrow `RecordBatch` that fits entirely in memory.

**Method Signature:**
```python
def write(
    batch: pyarrow.RecordBatch,
    target: str,
    user_context: Optional[str] = None,
    purpose: Optional[str] = None,
    contract_json: Optional[str] = None
) -> str
```

**Example:**
```python
import pyarrow as pa
import holonomy

batch = pa.RecordBatch.from_arrays([pa.array([1, 2])], names=["id"])
holonomy.write(batch, "s3://my-bucket/dataset.parquet", purpose="etl_job")
```

### `holonomy.Writer()` (Streaming Context Manager)
For massive datasets that exceed available RAM, use the `Writer` context manager. This opens a continuous multipart upload stream, allowing you to feed data incrementally via `.write_batch()`. The file is securely finalized and flushed when the context manager exits.

**Method Signature:**
```python
class Writer:
    def __init__(
        self,
        target: str,
        user_context: Optional[str] = None,
        purpose: Optional[str] = None,
        contract_json: Optional[str] = None
    ): ...
    
    def write_batch(self, batch: pyarrow.RecordBatch) -> None: ...
```

**Example:**
```python
import holonomy

with holonomy.Writer("s3://my-bucket/huge_dataset.parquet", purpose="etl_job") as writer:
    for chunk in generate_large_data_chunks():  # chunk is a pyarrow.RecordBatch
        writer.write_batch(chunk)
```

**Under the Hood:**

1. Python passes the `RecordBatch` directly to Rust via PyO3.
2. The `WriteOrchestrator` consumes the memory pointer.
3. **Audit Binding**: The `user_context` identity is bound into the audit logs and KMS request for the Data Encryption Key (DEK). This enforces an immutable audit trail of the encrypting identity without requiring cryptographic JWT validation (which is reserved for reads).
4. **Target Resolution**: The `target` URI (e.g., `https://<account>.r2.cloudflarestorage.com/bucket/dataset.parquet`) allows dynamic multipart uploader routing without mutating environment variables.
5. The dataset is chunked and processed securely.
6. **Concurrent Multipart Uploads**: Encrypted chunks are flushed directly to the target location via the `S3MultipartUploader`. Rather than sequentially awaiting each multi-megabyte chunk to reach S3/R2 over the network, `S3MultipartUploader` utilizes `tokio::spawn` to orchestrate massive parallel ingestion asynchronously, dramatically reducing network IO bottlenecks for large datasets.
7. **Graceful Drop Guard**: In the event that the Python process crashes, the `write` orchestrator panics, or the upload stream is cancelled prematurely, an RAII `Drop` guard automatically catches the dropped future and issues an `abort_multipart_upload` request to S3/R2 in the background. This prevents orphaned chunk accumulation and storage leakage on the target bucket.

### 4.1.1 Identity Resolution & Auditability
Because data ingestion (M2M pipelines) is strictly authorized by the KMS credentials (e.g. `GOOGLE_APPLICATION_CREDENTIALS`) rather than an end-user JWT, cryptographic validation is bypassed on writes. However, to ensure secure and accurate audit trails without leaking active Bearer tokens, the Python SDK intelligently resolves the `user_context` through 5 strict scenarios:

1. **Explicit Identity overrides Active ID Token**: If a developer explicitly provides a `user_context` (e.g., `"nightly-etl-pipeline"`) but their environment contains an active human ID token (with a `sub` claim), the explicit string is overridden by the human's `sub` claim to prevent accountability obfuscation, and a warning is logged.
2. **Explicit Identity with Active Access Token**: If a developer provides an explicit context but their environment contains a machine Access Token (no `sub` claim), their explicit context string is respected and logged.
3. **Implicit ID Token**: If no context is provided, the SDK reads the environment's `HOLONOMY_CREDENTIAL_FILE`, extracts the JWT payload, and if a `sub` claim exists, logs it securely.
4. **Implicit Access Token (M2M)**: If no context is provided and the environment token lacks a `sub` claim (typical for M2M workloads), the SDK extracts the `client_id` or `azp` claim to identify the service account, emitting a warning that a machine token was utilized.
5. **No Identity Provided**: If no context is provided and no tokens exist in the environment, the SDK safely falls back to recording `"undefined"` in the audit logs.

*Note: If an explicit `user_context` is provided that structurally resembles a JWT, the SDK will automatically extract its claims rather than logging the raw token string, preventing credential leakage in audit logs.*

## 4.2. Edge Quality Linters & Validations
Before encryption begins, the `WriteOrchestrator` invokes the `Validator`. This is the "upstream quarantine block."

### Hierarchical Data Contract Resolution
To prevent rigid lockouts while enforcing governance, `write()` resolves the schema contract hierarchically:

1. **Remote Schema Registry (`S3SchemaRegistryProvider`)**: Attempts to fetch the canonical schema contract from the remote metadata store (`HOLONOMY_POLICY_BUCKET`) based on the `target` URI. The engine automatically Base64-encodes (URL-safe, no padding) the target URI and looks for `[base64_target].json`.
2. **Local Fallback**: If no remote schema is registered, it checks for a `.holonomy_contract.json` file in the current working directory.
3. **Explicit Override**: If passed via the `contract_json` method argument, it will use that string explicitly (highest local precedence in scripts).
If no contract can be resolved across these three layers, the write is aborted.

### Automatically Generating Contracts
To significantly lessen the burden of manually creating these contracts from scratch, developers can use the Holonomy CLI to instantly generate a boilerplate JSON contract directly from any existing physical dataset:
```bash
holonomy inspect s3://my-bucket/dataset.parquet --generate-contract > .holonomy_contract.json
```
This inspects the metadata footprint of the target URI and scaffolds a structurally perfect dummy contract based on the underlying PyArrow data types.

- **Structural Constraints**: The validator strictly checks the PyArrow schema against the resolved JSON definitions.
- **Failure Mode**: If an unexpected column is present, or if an integer field is passed as a string, the ingestion process is immediately aborted (`Err`), returning a `PyRuntimeError`. This ensures that downstream consumers are never exposed to malformed structures.

## 4.3. Parquet Modular Encryption (PME)
Holonomy does not encrypt the entire Parquet file as a single blob. Instead, it leverages Parquet Modular Encryption (PME) via its `pme_encrypt.rs` module.

**Why PME is Critical:**

- **Column-level Granularity**: Data contracts and Policy Manifests (`EncryptionBlock`) are evaluated dynamically to determine exactly which columns must be scrambled.
- **Strict Cryptography**: Holonomy uses strict schema-based cryptographic directives; legacy regex fallback heuristics for encryption are forbidden, enforcing a fail-closed paradigm.
- **Query Optimization**: Because non-sensitive data remains plaintext, downstream tools can perform metadata pruning (like predicate pushdown) over the plaintext columns without paying the CPU cost of decrypting the sensitive ones.

**Encryption Algorithm:**
Holonomy utilizes hardware-accelerated **AES-GCM** natively supported by the Apache Parquet specification. This provides authenticated encryption, ensuring that both the confidentiality and the integrity of the data chunks are mathematically guaranteed before they are parsed into Arrow arrays.

## 4.4. Time-Based DEK Caching (Streaming Writes)
During streaming ingestion (where millions of rows are continually flushed to object storage), fetching Data Encryption Keys (DEKs) from the KMS for every single file partition can exhaust KMS API quotas and introduce significant latency.

To mitigate this, Holonomy implements a `WriteDekCache` that operates inside `PmeEncryptor`.

- When a write is initiated, Holonomy generates a raw cryptographically secure DEK in-memory.
- It calls the KMS to wrap this key *once*.
- Both the plaintext key and the wrapped key are stored in a thread-safe global `DashMap` cache keyed by `target | purpose | column`.
- Future continuous writes to the same target/purpose combination reuse this cached DEK seamlessly.

**Recommendation for Users:** DEKs are automatically rotated (flushed from the cache) based on a default 15-minute Time-To-Live (TTL). This ensures optimal performance without sacrificing security. For most streaming architectures, the default 15-minute TTL provides the best balance of throughput and cryptographic rotation.
