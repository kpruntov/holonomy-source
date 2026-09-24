# 5. The Consumer Path: High-Performance Analytics (Reading)

## 5.1. The `holonomy.read()` and `holonomy.scan()` APIs
The consumer path pulls data from remote storage, performs the necessary policy checks and unwrapping, decrypts the chunks, and bridges the result into Python. Holonomy provides two APIs for this depending on whether you want all data at once or as a lazy stream.

### `holonomy.read()` (In-Memory Array)
Use this for eagerly reading data into memory as a single PyArrow `Array` or `Table`.

**Method Signature:**
```python
def read(
    target: str,
    user_context: Optional[str] = None,
    columns_to_read: Optional[List[str]] = None,
    purpose: Optional[str] = None,
    filters: Optional[pyarrow.compute.Expression] = None,
    contract_json: Optional[str] = None,
    assumed_role: Optional[str] = None
) -> pyarrow.Array
```

**Example:**
```python
import holonomy

# Read specific columns for a specific purpose
arrow_array = holonomy.read(
    "s3://my-bucket/dataset.parquet",
    purpose="data-science-analytics",
    columns_to_read=["user_id"]
)
```
> [!NOTE]
> **Why is `columns_to_read` a list for `read()`?**
> Even though `read()` can only return a single 1D `pyarrow.Array`, its signature uses an `Optional[List[str]]` to maintain strict API symmetry with `scan()`. However, you should provide exactly one column. If you provide a list of multiple columns, the Rust engine will only extract and read the first one, dropping the rest.

### `holonomy.scan()` (Lazy Stream)
For massive datasets, use `scan()` to return a lazy `pyarrow.RecordBatchReader`. This allows downstream engines (like Polars or DuckDB) to pull data in chunks without loading the entire dataset into RAM.

**Method Signature:**
```python
def scan(
    target: str,
    user_context: Optional[str] = None,
    columns_to_read: Optional[List[str]] = None,
    purpose: Optional[str] = None,
    filters: Optional[pyarrow.compute.Expression] = None,
    contract_json: Optional[str] = None,
    assumed_role: Optional[str] = None
) -> pyarrow.RecordBatchReader
```

**Example:**
```python
import holonomy
import polars as pl
import pyarrow.compute as pc

# Lazily scan with predicate pushdown
stream = holonomy.scan(
    "s3://my-bucket/dataset.parquet",
    purpose="data-science-analytics",
    filters=(pc.field("age") > 21)
)

# Consume with Polars seamlessly
lazy_df = pl.scan_pyarrow_dataset(stream)
```

**Under the Hood (The Read Orchestration Flow):**
1. The user requests specific columns from a dataset using `holonomy.scan()`.
2. The `ScanOrchestrator` fetches the Parquet Footer to extract the cryptographic metadata for those columns.
3. If `filters` (a PyArrow `Expression`) are provided, they are serialized to JSON in Python, passed into Rust, and evaluated against the Parquet row group statistics (min/max bounds). Entire row groups are pruned *before* decryption and *before* HTTP data fetches, saving significant memory and compute (Predicate Pushdown).
4. It resolves the Data Encryption Key (DEK) via the `CryptoManager`.
5. It computes the active byte-ranges for the projected columns. Unselected columns strictly do not trigger HTTP Range requests (saving memory and egress).
6. It issues concurrent HTTP Range requests for all active columns simultaneously.
7. The `simd_ops` engine decrypts the chunks and applies RLS per-column.
8. The resulting RecordBatch is assembled and returned to Python.

## 5.2. Working with Local Compute Runtimes
Because Holonomy operates using the zero-copy Arrow memory model, it is fully agnostic to the downstream execution engine. 

### Integration with Polars
Polars natively understands Arrow structures. Passing the result of `holonomy.read()` into Polars takes `O(1)` time—there is no memory copying or iteration.
```python
import polars as pl

# 1. Decrypt directly into C-contiguous memory
# We provide 'purpose' to ensure the GovernanceManager evaluates our request against the Master Policy.
arrow_array = holonomy.read("s3://bucket/data", user_context="analyst-role", columns_to_read=["secret_column"], purpose="data-science-analytics")

# 2. Wrap the memory in a Polars DataFrame instantly
df = pl.from_arrow(arrow_array)
```

For large datasets, use the lazy `holonomy.scan()` interface, which leverages the Arrow C Stream Interface (`FFI_ArrowArrayStream`). This defers execution and allows query engines to push down predicates and projections:
```python
# Returns a pyarrow.RecordBatchReader
stream = holonomy.scan("s3://bucket/data", user_context="analyst-role", columns_to_read=["user_id", "email"])

# Polars can lazily consume this stream
lazy_df = pl.scan_pyarrow_dataset(stream)
```

### Integration with DuckDB
Similarly, DuckDB can execute relational SQL directly over active Arrow memory pointers:
```python
import duckdb
import pyarrow as pa

arrow_array = holonomy.read("s3://bucket/data", user_context="analyst-role", columns_to_read=["secret_column"], purpose="data-science-analytics")
my_arrow_table = pa.Table.from_arrays([arrow_array], names=["secret_column"])

# Use from_arrow to robustly query the table without relying on Python scope resolution
res = duckdb.from_arrow(my_arrow_table).query("my_table", "SELECT secret_column FROM my_table WHERE secret_column IS NOT NULL").df()
```

DuckDB can also query the lazy stream directly, processing chunks as they are decrypted without loading the entire dataset into memory:
```python
stream = holonomy.scan("s3://bucket/data", user_context="analyst-role", columns_to_read=["user_id", "email"], purpose="data-science-analytics")

# Explicitly bind the stream to a DuckDB relation for safe execution in ETL environments
res = duckdb.from_arrow(stream).query("stream_tbl", "SELECT * FROM stream_tbl").df()
```

## 5.3. Dynamic Column Masking & RLS
Holonomy doesn't just decrypt data; it actively enforces Row-Level Security (RLS) and masking rules during the read process via the `GovernanceManager` and `simd_ops` routines.

### How the Kernel Evaluates Masking (Without `contract_json`)
Unlike `holonomy.write()` which requires a `contract_json` to define the data schema, `read()` and `scan()` do not require it. This is because **governance policies are centralized, not data-attached**. 
1. When `read()` or `scan()` is invoked, the `GovernanceManager` receives the `target`, the `purpose`, and the **User Identity** (JWT or local context).
2. The user identity is checked against the central `holonomy_master_policy.json` to find their roles. If the user belongs to multiple roles (e.g. `data-scientist` and `marketing`), the `purpose` string is used to disambiguate. The engine looks up the `purpose_bindings` map in the policy to dynamically resolve the active role for the query.
3. If the active role lacks plaintext clearance for a specific **encrypted** column, the `GovernanceManager` dynamically instructs `simd_ops` to apply the masking rule defined in the master policy.

### Graceful Degradation
If a user requests a column they do not have full plaintext clearance for (based on the `purpose` provided and their role inside the master policy), Holonomy applies graceful degradation:
- Instead of crashing the application, it returns the column securely masked.
- Using vectorized SIMD operations, string columns may be replaced with fixed constants (e.g., `***MASKED***`) or `NULL` substitutions.
- This allows data science pipelines to continue running structurally, even when dealing with highly sensitive datasets where certain cell values are strictly forbidden.
