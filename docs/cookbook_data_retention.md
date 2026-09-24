# Cookbook: Crypto-Shredding & Data Retention

Data retention policies mandate that Personally Identifiable Information (PII) must be completely expunged after a certain period (e.g., 2 years after collection). However, businesses often want to keep the non-sensitive, anonymized behavioral data indefinitely for historical trend analysis.

## The Challenge
In a standard Data Lake, data is stored in massive Parquet files partitioned by time (e.g., `year=2024/month=01`). When the retention period for January 2024 expires, data engineers must spin up an expensive Databricks or Snowflake cluster, load all the files for that month, drop the PII columns, and rewrite the anonymized datasets back to S3. 

Executing these rolling purges costs organizations immense amounts of compute money and engineering maintenance.

## The Holonomy Solution: Partition-Level Crypto-Shredding
Because Holonomy utilizes Parquet Modular Encryption (PME) where sensitive columns can be encrypted with distinct Key Encryption Keys (KEKs) wrapped by your central KMS, you can achieve instantaneous, mathematically guaranteed deletion without rewriting a single byte of storage.

This technique is known as **Crypto-Shredding**.

### The Architecture
1. **Partition-Level Encryption:** When your ETL pipeline writes the Parquet files to S3, it partitions them by time (e.g., monthly). Crucially, Holonomy encrypts the sensitive columns (like `email`) for that specific partition using a KEK unique to that month. The non-sensitive columns (like `transaction_amount`) are left unencrypted.
2. **The Expiration:** When the retention period for that month expires, you do not touch the Parquet files in S3. Instead, you log into your AWS KMS or Azure Key Vault and **permanently delete the KEK for that month**.

### The Execution
The moment the KMS key is destroyed, the PII columns for that specific partition instantly turn into an irreversible mash of encrypted bytes. 

```python
import holonomy

# The Parquet file in S3 STILL physically contains the encrypted bytes.
# However, because the KMS key was destroyed, Holonomy cannot unwrap the DEK.
# The sensitive PII is mathematically unrecoverable and skipped.
# The analyst seamlessly receives the historical data, fully anonymized.
table = holonomy.read("s3://data-lake/year=2024/month=01/")
```

## Business Impact
- **Zero Compute Rewrite Costs**: You can execute massive monthly PII retention purges in milliseconds by simply deleting a key in AWS KMS, entirely eliminating the need to rewrite terabytes of historical Parquet data.
- **Indefinite Analytical Value**: Because only the sensitive columns are shredded, your data science teams retain permanent access to the unencrypted, anonymized columns for long-term machine learning models.
- **Absolute Cryptographic Guarantee**: Crypto-shredding is a mathematical absolute. Even if an attacker steals the expired Parquet files, the PII is permanently inaccessible to everyone in the universe.
