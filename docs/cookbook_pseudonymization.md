# Cookbook: Pseudonymization for Analytics

One of the core tensions in data engineering is balancing privacy with analytical utility. Data scientists need to track user journeys across datasets, but modern privacy regulations and best practices require that Personally Identifiable Information (PII) is not freely accessible.

## The Challenge
If you simply `REDACT` or nullify an `email` column, data scientists lose the ability to group records by user or perform `JOIN` operations across different tables. Conversely, giving them plaintext access violates compliance mandates.

## The Holonomy Solution: Salted Deterministic Hashing
Holonomy solves this by offering a native `HASH` masking strategy. Instead of destroying the data, the Rust core computes a deterministic, **salted** SHA-256 digest of the identifier *in-memory* before the data is handed to the Python environment. 

This generates a **salted deterministic pseudonym designed for cross-dataset JOIN equality**. Because the same global salt (configured via `hash_salt`) is applied universally across all queries and datasets, data scientists can still perform `JOIN` and `GROUP BY` operations securely, while remaining protected against dictionary or rainbow-table attacks.

### The Policy Architecture
You target the semantic `pii` tag (or a specific column) in your `holonomy_master_policy.json` and set the action to `HASH`.

```json
{
  "version": "1.0",
  "purpose_bindings": {
    "analytics": "data-analyst"
  },
  "principals": {
    "data-analyst": {
      "global_row_filters": [],
      "selective_row_filters": [],
      "column_masks": {},
      "tag_masks": {
        "pii": "HASH"
      }
    }
  }
}
```

### The Execution
When the analyst reads the data, they never see `alice@example.com`. Instead, they see a hex digest.

```python
import holonomy
import polars as pl

# The analyst reads the dataset.
table = holonomy.read("s3://data-lake/transactions.parquet")
df = pl.from_arrow(table)

# The analyst can perfectly track the user's cohort behavior
# and join against other tables that also hashed the PII.
user_spend = df.group_by("email").agg(pl.col("amount").sum())
```

## Business Impact
- **Maintained Utility**: Analysts can still perform primary-key joins and behavioral clustering.
- **Privacy Guardrail**: The raw PII never enters the analyst's constructed data frame, aligning with robust pseudonymization practices.
