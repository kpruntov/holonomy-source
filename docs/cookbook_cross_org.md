# Cookbook: Cross-Org Data Sharing

Sharing sensitive datasets with external partners, vendors, or contractors is historically a logistical nightmare involving custom API endpoints, shared cloud warehouses, or manually creating anonymized copies of datasets (ETL).

Holonomy provides two distinct approaches to cross-organization sharing, depending on the level of trust you have with the 3rd party.

## Approach 1: Zero-Effort Plaintext Columns (Recommended)
The absolute most secure—and easiest—way to share data with a 3rd party is to utilize the native capabilities of Parquet Modular Encryption (PME). PME allows you to encrypt *specific* columns while leaving the rest of the dataset in completely standard plaintext.

**The Setup:**
1. You configure Holonomy to encrypt only the highly sensitive columns (like PII or financial metrics) with your KMS. 
2. The remaining columns are written to the Parquet file as standard, unencrypted data.
3. You grant the partner organization simple read access to the raw `.parquet` files in your S3 bucket.

**The Result:** 
The partner does not need access to your KMS. They do not need *any* cryptographic keys. They simply read the Parquet file using the standard Holonomy consumer role (or even raw PyArrow). They can seamlessly read all the unencrypted columns, while the sensitive columns remain impenetrable mathematical blobs. This requires zero ETL on your end and offers an absolute, zero-trust cryptographic guarantee.

## Approach 2: Soft Controls via Row-Level Security (High Trust Required)
Sometimes a partner *does* need access to an encrypted column, but you want to restrict *which rows* they can see (e.g., they should only see rows where `client_id = vendor_a`).

In this case, you must grant the partner Cross-Account IAM access to your KMS to unwrap the DEK for the entire column. You then rely on Holonomy's `holonomy_master_policy.json` to filter the rows out in their local memory:

```json
{
  "version": "1.0",
  "purpose_bindings": {
    "vendor-analytics": "vendor-a"
  },
  "principals": {
    "vendor-a": {
      "global_row_filters": ["client_id = 'vendor-a-id'"],
      "selective_row_filters": [],
      "column_masks": {},
      "tag_masks": {}
    }
  }
}
```

> **⚠️ CRITICAL SECURITY WARNING**
>
> Relying on Row-Level Security (RLS) or Data Masking for cross-organization sharing is a **Soft Control**. Because the partner is executing Holonomy on *their own hardware* and your KMS has granted them the key to decrypt the column, the data is decrypted in their local RAM before the `client_id` filter drops the rows.
>
> A malicious partner could theoretically attach a memory debugger (like `gdb`) to the Holonomy process and dump the RAM to extract the decrypted rows belonging to their competitors. 
>
> This approach should **only** be used if you have strong contractual trust with the partner, or if they are executing the Holonomy client within an isolated, trusted execution environment (TEE) or secure workspace that you control.
