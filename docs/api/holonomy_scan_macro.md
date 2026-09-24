# `holonomy_scan` Macro Reference

The `holonomy_scan` macro is the primary interface for fetching data from the Holonomy Policy and Governance Engine directly into DuckDB. It securely fetches and decrypts data while ensuring fine-grained access control based on active roles.

## Syntax

```sql
SELECT * FROM holonomy_scan('target', 'purpose', ['projection1', 'projection2']);
```

### Arguments

1.  **`target`** *(VARCHAR)*: The dataset identifier or URN to scan.
2.  **`purpose`** *(VARCHAR)*: The business purpose for data access (evaluated against governance policies).
3.  **`projections`** *(VARCHAR[])*: **Crucial for Performance.** An explicit list of column names you intend to use. 

*(Note: The macro automatically fetches the user's active token and assumed role from DuckDB session variables `holonomy_token` and `holonomy_assumed_role`.)*

## Projections (Why they matter)
Because `holonomy_scan` uses DuckDB's highly optimized `arrow_scan` native C++ table function to achieve **Zero-Copy** memory performance, it relies on you explicitly defining projections.

**What happens if you omit the `projections` array or pass an empty list?**
The Holonomy engine will fetch and KMS-decrypt **every single column** in the dataset. DuckDB will then filter down the result to only the columns you `SELECT`ed. For datasets with PII or massive payloads, this causes severe IO overhead and unnecessary cryptographic operations. 

**Always specify the exact columns you need in the `projections` list.**

## Warnings & Limitations

### 1. No Filter Pushdown
The `arrow_scan` engine does not currently push down SQL `WHERE` clauses into the Holonomy engine. If you run:
`SELECT * FROM holonomy_scan(...) WHERE id = 5;`
Holonomy will fetch the entire dataset, decrypt it, and DuckDB will filter it down to `id = 5` in memory. If you require server-side filtering, future updates will introduce explicit predicate arguments to the macro.

### 2. Prepared Statements & Caching (CRITICAL)
**Do not use `holonomy_scan` inside DuckDB `PREPARE` statements.** 
The data is delivered via a single-pass Arrow C Data Interface stream. If a query caches the stream pointer (e.g., via a prepared statement executed multiple times), DuckDB will attempt to read from a consumed stream, resulting in a **Segmentation Fault** or memory corruption. `holonomy_scan` must be invoked dynamically on every query.

## Under the Hood: Zero-Copy Performance
The macro utilizes an internal DuckDB scalar function (`holonomy_build_arrow_stream`) which initializes the `ScanOrchestrator`, negotiates the schema, and returns a C-pointer to the Arrow Stream directly to DuckDB's execution engine. Data is mapped natively to DuckDB vectors without deep copying strings or buffers.
