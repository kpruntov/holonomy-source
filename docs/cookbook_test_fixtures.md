# Cookbook: Generating Test Fixtures from Production Data

One of the most persistent bottlenecks in software engineering is generating realistic test data. Synthetic data generation often misses complex edge cases or subtle relational constraints present in the real world, leading to a situation where code passes locally but fails in production.

## The Challenge
Developers and QA engineers want to use real production data to populate local test databases or run unit tests. However, pulling raw production data locally is a massive security and compliance violation, as it exposes PII (Personally Identifiable Information), financial records, and proprietary secrets to developer workstations.

## The Holonomy Solution: Purpose-Driven Data Extracts
Holonomy allows you to securely project a highly masked, heavily filtered slice of production data into a developer's local environment. You can define a specific `test-fixture-generation` purpose binding in your `holonomy_master_policy.json` that aggressively pseudonymizes and filters the data.

### The Execution
Instead of downloading the raw file or running a heavy ETL job, developers simply use Holonomy to stream the data, applying the test purpose, and write the result out to a local dummy file.

```python
import holonomy
import polars as pl
import os

# Set your identity context to the developer test scope
os.environ["HOLONOMY_CREDENTIAL_FILE"] = "/var/run/secrets/local_dev_token.jwt"

# Stream the data from the production S3 bucket.
# The policy engine ensures all PII is hashed, financial columns are nullified,
# and rows are sampled/filtered down to a safe testing subset.
table = holonomy.read(
    "s3://production-data-lake/transactions_2024.parquet",
    purpose="test-fixture-generation"
)

# Use Polars to write the fully scrubbed data to a local Parquet file
# which can now be safely committed to the test suite or loaded into a local DB.
df = pl.from_arrow(table)
df.write_parquet("local_test_fixture.parquet")
```

### 💡 Infrastructure & Security Tips for Test Fixtures
- **Aggressive Subsampling:** In your policy definition for `test-fixture-generation`, use a global row filter to ensure developers only ever pull a tiny fraction of the data (e.g., `id % 1000 = 0`).
- **One-Way Masks:** Rely heavily on `HASH` or `REDACT` masking for this purpose. You want to ensure the data is mathematically decoupled from the original production subjects.

## ⚠️ Evaluate with Caution
While Holonomy *can* be used to pipe production data into local test fixtures, **you must use this capability with extreme caution**.

1. **Inference Attacks:** Even if you hash emails and redact names, the remaining unencrypted columns (like `transaction_amount`, `timestamp`, `zip_code`) might be unique enough to deanonymize a user (e.g., identifying a CEO by a highly specific transaction at a specific time).
2. **Data Spill Risk:** If a policy is misconfigured (e.g., a new sensitive column is added to production but forgotten in the masking policy), developers might accidentally pull raw PII into their local laptops, leading to a sprawling compliance incident.

**Best Practice:** Whenever possible, prefer sophisticated synthetic data generation tools (like Faker or specialized ML generators) over masked production data. Use Holonomy for test fixtures *only* when the relational complexity of the data cannot be synthetically reproduced, and subject those specific policy rules to rigorous, multi-party security reviews.
