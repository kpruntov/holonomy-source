# 6. Advanced Features & Edge Case Handling

## 6.1. Managing Schema Evolution & Schema Drift
When pointing Holonomy at a remote S3 directory (e.g., `s3://my-bucket/dataset/`), the system must handle the reality that Parquet files created months apart may have different schemas.

Holonomy's `schema::drift` module actively analyzes directories for structural mutations across partition bounds.
If Holonomy detects that `part-001.parquet` contains a different column layout or type structure than `part-002.parquet`, it emits a `WARNING: Structural mutations (schema drift) detected` alert to `stderr`.


## 6.2. Optimizing Network Overhead
Holonomy is engineered to ensure that reading encrypted data over the network is as fast as reading plaintext data.

### Targeted HTTP Range Requests
Inside the `S3Client`, Holonomy avoids downloading the entire multi-gigabyte Parquet file.

1. **Speculative Footer Fetching**: It issues an HTTP `Range` request for the last 64KB of the file to grab the Parquet metadata in a single network round-trip.
2. **Column Extraction**: By analyzing the footer, it calculates the exact byte offsets of the requested `columns_to_read`.
3. **Bounded Concurrency**: It issues highly concurrent HTTP requests (strictly bounded to `100` max in-flight requests to prevent TCP port exhaustion) to pull down only those specific chunks. 

### Token Caching (`DashMap`)
Every encrypted Parquet file requires a KMS round-trip to unwrap its DEK. Doing this for 1,000 partition files would cripple performance. 
The `dek_cache.rs` module leverages a highly concurrent, lock-free hash map (`DashMap`) to cache decrypted DEKs in local memory. If a subsequent file shares the same KEK ID, the unwrapping phase is bypassed completely.

## 6.3. The CLI Toolbelt: `holonomy inspect`
Holonomy bundles a powerful, standalone CLI binary designed for DevSecOps and Platform teams to inspect structural schemas without touching raw data.

**Extracting ASCII Schemas:**
You can target remote URIs directly from your terminal:
```bash
holonomy inspect s3://my-bucket/dataset/
```
*Outputs:*
```
+-------------+---------------+----------------------+
| Column Name | Physical Type | Logical Type (Arrow) |
+-------------+---------------+----------------------+
| id          | INT64         | None                 |
| email       | BYTE_ARRAY    | String               |
+-------------+---------------+----------------------+
```

**Generating Baseline Policies (`-g`):**
Instead of manually mapping columns to a JSON policy structure by hand, you can instruct the CLI to automatically build the master policy JSON template directly from the remote Parquet footer:
```bash
holonomy inspect s3://my-bucket/dataset/ --generate-contract --output policy.json
```
This safely binds the URI and maps all detected columns to `UNCLASSIFIED_TODO`, drastically reducing setup friction for new datasets.
