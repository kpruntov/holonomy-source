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
The partner does not need access to your KMS. They do not need *any* cryptographic keys. They simply read the Parquet file using the standard Holonomy consumer role (or even raw PyArrow). They can seamlessly read all the unencrypted columns, while the sensitive columns remain impenetrable mathematical blobs. This requires no additional ETL on your end and provides a strong cryptographic boundary.

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


### 💡 Infrastructure & OS-Level Tips for Soft Controls
If you must rely on Approach 2 (Soft Controls via RLS), the 3rd party is decrypting data in their local RAM. You must enforce OS-level constraints on the machines executing the queries:
- **No Local Admin Access:** Analysts running Holonomy must operate as standard users, not `root` or `Administrator`. This prevents them from attaching memory debuggers to extract raw DEKs.
- **Disable Core Dumps:** Ensure the OS is configured to block crash dumps (`ulimit -c 0` on Linux/macOS). If the Python process crashes, a core dump could persist the plaintext data to disk.
- **Ephemeral Workspaces:** Rather than allowing partners to download data to local laptops, provide them with ephemeral Cloud Workspaces (e.g., AWS WorkSpaces, GitHub Codespaces) where you can enforce these OS-level network and memory constraints centrally.
