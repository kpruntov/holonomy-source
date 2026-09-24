# Holonomy Python SDK API

This document describes the Python API wrapper for the Holonomy Governance SDK.

## Core Functions

### `holonomy.read(target, user_context=None, columns_to_read=None, purpose=None, filters_json=None, contract_json=None, assumed_role=None)`

Reads a single column from a dataset securely into an Apache Arrow Array.

**Parameters:**
- `target` (*str*): S3 URI (e.g., `s3://bucket/key.parquet`) or local file path (e.g., `file:///path/to/file.parquet`) to the dataset.
- `user_context` (*str, optional*): A JSON Web Token (JWT) or identity string used for authentication, Row-Level Security (RLS), and dynamic data masking. Although marked as optional in the signature, omitting it will raise a `ValueError`.
- `columns_to_read` (*list of str, optional*): A list containing exactly one column name to read. If not exactly one column, a `ValueError` is raised.
- `purpose` (*str, optional*): Business purpose for audit logging and contextual policy evaluation.
- `filters_json` (*str, optional*): Not used in `read()`. (Provided for API signature compatibility only).
- `contract_json` (*str, optional*): Inline JSON string representing a data contract. Overrides any discovered contracts.
- `assumed_role` (*str, optional*): A specific role to assume if the `user_context` grants multiple roles.

**Returns:**
- `pyarrow.Array`: A zero-copy pointer from Rust to the decrypted and masked column data.

**Raises:**
- `ValueError`: If `user_context` is not provided or if `columns_to_read` does not contain exactly one column.
- `RuntimeError`: If decryption, policy validation, or storage access fails.

**Recommendations & Limitations:**
- `read()` is strictly limited to fetching a single column as a PyArrow Array. If you need multiple columns or a tabular structure, you must use `holonomy.scan()`.
- The entire column data is loaded into memory at once. For large datasets, use `scan()` instead to stream the data.

### `holonomy.scan(target, user_context=None, columns_to_read=None, purpose=None, filters_json=None, contract_json=None, assumed_role=None)`

Lazily scans a dataset securely, yielding an Apache Arrow `RecordBatchReader`.

**Parameters:**
- `target` (*str*): S3 URI or local file path to the dataset.
- `user_context` (*str, optional*): A JWT or identity string used for RLS and data masking. Must be provided or a `ValueError` is raised.
- `columns_to_read` (*list of str, optional*): List of specific columns to project. If `None`, all columns defined in the schema/contract are projected.
- `purpose` (*str, optional*): Business purpose for audit logging.
- `filters_json` (*str, optional*): JSON string representing pushdown predicates (e.g., `[{"column": "age", "op": "Gt", "value": "18"}]`). Used to prune row groups before fetching data.
- `contract_json` (*str, optional*): Inline JSON string representing a data contract.
- `assumed_role` (*str, optional*): A specific role to assume.

**Returns:**
- `pyarrow.RecordBatchReader`: An iterable stream of PyArrow `RecordBatch` objects.

**Raises:**
- `ValueError`: If `user_context` is missing.
- `RuntimeError`: If initialization, S3 communication, or decryption fails.

**Recommendations & Limitations:**
- **Recommendation:** Use `scan()` as the primary method for analytics (e.g., passing the result directly to Polars or DuckDB) to minimize memory footprint.
- **Limitation:** While `scan()` pipelines I/O (prefetching footers and streams), performance may still be bottlenecked by network latency when processing a large number of very small Parquet files.

### `holonomy.write(batch, target, user_context=None, purpose=None, contract_json=None)`

Validates, encrypts, and writes a single `RecordBatch` to storage using policies mapped to the target.

**Parameters:**
- `batch` (*pyarrow.RecordBatch*): The data to write.
- `target` (*str*): S3 URI or local path destination.
- `user_context` (*str, optional*): Identity string for audit logging. Does not require a strict JWT. If omitted or passed as free text, it will be used as a KMS encryption context. If an environment JWT is found, it will automatically override this value with the `sub` claim.
- `purpose` (*str, optional*): Business purpose for the write operation.
- `contract_json` (*str, optional*): Data contract override for schema validation.

**Returns:**
- `str`: Returns `"Upload successful"` upon completion.

**Raises:**
- `RuntimeError`: If schema validation (linting) fails or S3 upload fails.

**Recommendations & Limitations:**
- **Limitation:** The `write()` function accepts exactly one `RecordBatch`. To write streaming data or multiple batches incrementally, use the `holonomy.Writer` context manager instead.

### `holonomy.Writer`

A Python context manager class for streaming multiple `RecordBatch` objects to a single encrypted dataset.

**Constructor Parameters:**
- `target` (*str*): Destination S3 URI or local path.
- `user_context` (*str, optional*): Identity string for audit logging. Can be free text. Overridden by environment JWT if present.
- `purpose` (*str, optional*): Business purpose. Required.
- `contract_json` (*str, optional*): Data contract override.

**Methods:**
- `write_batch(batch: pyarrow.RecordBatch)`: Encrypts and uploads the batch asynchronously.

**Example:**
```python
with holonomy.Writer("s3://bucket/data.parquet", user_context="token", purpose="etl") as writer:
    writer.write_batch(batch1)
    writer.write_batch(batch2)
```

**Recommendations & Limitations:**
- **Recommendation:** The `Writer` uses a dedicated Tokio background task to pipeline encryption and S3 multipart uploads. Always use the context manager (`with ...`) to ensure resources are cleaned up and the multipart upload is finalized safely on exit. If an exception occurs inside the `with` block, the upload is aborted to prevent corrupt data.

### `holonomy.init(kms_endpoint=None, kms_region=None, policy_bucket=None, cache_ttl_hours=None)`

Explicitly configures the Holonomy Core environment programmatically.

**Parameters:**
- `kms_endpoint` (*str, optional*): Custom AWS KMS endpoint URL (e.g., for LocalStack testing).
- `kms_region` (*str, optional*): AWS region for KMS.
- `policy_bucket` (*str, optional*): Central S3 bucket for downloading master policies.
- `cache_ttl_hours` (*int, optional*): Time-to-live for cached DEKs and policies.

**Returns:**
- `None`

**Raises:**
- `RuntimeError`: If Holonomy has already been initialized (either explicitly or implicitly).

**Recommendations & Limitations:**
- **Recommendation:** Call `init()` at the very beginning of your script if you need to override environment variables. If not called, Holonomy will implicitly initialize with default settings on the first read/write operation.