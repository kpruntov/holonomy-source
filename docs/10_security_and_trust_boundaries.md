# 10. Security and Trust Boundaries

> **Legal Disclaimer**
> The term "guarantee" in this document refers strictly to the intended mathematical and cryptographic behavior of the software architecture. It does not constitute a legal obligation, liability, or warranty on the part of Kirill Pruntov or any contributors. Holonomy is provided "AS-IS" under the Business Source License. It is the sole responsibility of the deploying organization to ensure their infrastructure, KMS configuration, and deployment topology meet their specific regulatory and security requirements.

When integrating Holonomy into your enterprise data architecture, it is essential to understand the distinction between cryptographic boundaries and software-enforced guardrails. Holonomy operates under a "Soft Governance" philosophy, actively choosing developer experience and zero-copy performance over absolute, air-gapped cryptographic isolation.

This document clearly defines Holonomy's trust boundaries.

## 1. Hard Guarantees (Cryptographic Isolation)

The only absolute, mathematical boundary Holonomy relies on is the **KMS (Key Management Service) boundary**. 

Because Holonomy utilizes Parquet Modular Encryption (PME) via Envelope Encryption:
- Your Parquet columns are encrypted with a unique Data Encryption Key (DEK).
- That DEK is encrypted with a master Key Encryption Key (KEK) stored in AWS KMS, Azure Key Vault, or HashiCorp Vault.

**The Cryptographic Boundary:** If a user's cloud identity (e.g., their AWS IAM Role) does not have explicit `kms:Decrypt` permissions for the specific KEK, it is mathematically impossible for them to decrypt the column. Even if they bypass Holonomy entirely and use raw `boto3` or `pyarrow`, the data remains secure. 

To achieve a "Hard Boundary", you must map specific sensitive columns to dedicated KMS keys, and restrict those KMS keys via strict cloud IAM policies.

### Fail-Closed Cryptographic Assertions
Holonomy actively protects against ingestion misconfigurations (e.g., a data engineer accidentally writing a sensitive column as plaintext Parquet). 
The `holonomy_master_policy.json` contains an `EncryptionBlock` that strictly defines which semantic tags (e.g., `["pii"]`) or specific columns (e.g., `["email"]`) **MUST** be physically encrypted. 
During the read path, Holonomy inspects the Parquet footer. If a column is required to be encrypted by the Policy Manifest but is found in plaintext, Holonomy immediately aborts the read with a `DataLeakPrevented` error. This fail-closed mechanism guarantees that mistakenly unencrypted sensitive data cannot silently slip through the governance engine.

## 2. Soft Controls (In-Memory Guardrails)

Once the KMS successfully unwraps the DEK, the data enters Holonomy's memory space. From this point forward, all governance is considered a **Soft Control**. 

### Row-Level Security (RLS) and Data Masking
RLS and data masking are evaluated *post-decryption* in the analyst's local RAM. 
- Holonomy evaluates the signed `holonomy_master_policy.json` manifest and applies filters or masking functions (like `REDACT` or `HASH`) before handing the data pointer to the Python environment.
- **The Limitation:** Because this happens on the client side (the analyst's machine), a malicious internal actor with administrative access to their machine could attach a memory debugger (like `gdb`), dump the RAM, or intercept the Rust process to extract the plaintext data before the mask is applied. 

These controls are designed as guardrails to prevent well-intentioned data scientists from accidentally viewing or leaking sensitive data, not to thwart malicious insiders with root access to the execution environment.

### Cryptographic Material Lifecycle (DEKs)
To optimize performance, Holonomy maintains an internal `DekCache` of unwrapped Data Encryption Keys (DEKs) with a strict 5-minute Time-To-Live (TTL). When a DEK expires from this cache, Holonomy guarantees the memory is mathematically zeroized (`ZeroizeOnDrop`).

However, passing the DEK into the upstream Apache Parquet Rust library requires copying it into a standard `Vec<u8>` vector. Because the Parquet library takes ownership of this vector and relies on the global system allocator to drop it, Holonomy cannot actively zeroize this specific copy without triggering Use-After-Free (UAF) corruption. 
**The Limitation:** This means a copy of the plaintext DEK may linger in the process heap until the OS allocator reuses the memory. Consequently, if a process crash occurs, the plaintext DEK could be exposed in the resulting crash dump.

### Memory Isolation & Zero-Copy
Holonomy guarantees high performance by handing a native Apache Arrow memory pointer back to Python. This memory is not cryptographically isolated (e.g., via Intel SGX). Isolating it would require expensive serialization, destroying the zero-copy benefits. As a result, protecting against local memory inspection or crash dumps is explicitly out of scope for Holonomy's threat model.

### Policy Signature Trust Chain
Holonomy uses Ed25519 signatures to separate policy authorship (Security Team) from policy execution (Data Scientists). 
However, the trust chain relies entirely on how the `HOLONOMY_PUBLIC_KEY` environment variable is injected into the execution environment:
- **Managed Environments (JupyterHub, ECS, Databricks):** The infrastructure team injects the public key as a locked environment variable. The ordinary analyst cannot change it, ensuring a strong trust chain.
- **Local Laptops:** If the analyst runs Holonomy locally, they have administrative access to their own environment variables. An authorized but malicious analyst could theoretically replace `HOLONOMY_PUBLIC_KEY` with their own key, sign a permissive policy, and bypass the governance rules (another reason this is a **Soft Control**).

**Important Limitations (Rollback Attacks):** Currently, the `holonomy_master_policy.json` schema does not support expiration dates (`expires_at`) or monotonically increasing sequence checks. If a security team signs a restrictive `v2.0` policy to replace a permissive `v1.0` policy, an attacker with a copy of `v1.0` can continue to use it indefinitely because the cryptographic signature on `v1.0` remains mathematically valid.

### Telemetry & Audit Logging
Holonomy broadcasts access events to a centralized sink. Because this executes on the edge, a malicious user could manipulate their local firewall to block outbound HTTP requests to the telemetry server. Audit logging is a best-effort compliance trail.

### Authorized User Data Sprawl (Data Exfiltration)
If an analyst is legitimately authorized to access the plaintext data, Holonomy provides the masked/unmasked DataFrame to their local environment. Holonomy **cannot** prevent that authorized analyst from subsequently writing the plaintext data back to a new S3 bucket, saving it to a local CSV, or manually using `boto3`/`pyarrow` to perform a custom decryption. 
Once the data is legitimately decrypted into the analyst's memory space, technical enforcement ends. Companies must rely on standard Data Loss Prevention (DLP) tools, endpoint monitoring, network egress controls, and proper organizational training to prevent authorized users from sprawling or exfiltrating sensitive data.

## 3. Summary

| Feature | Boundary Type | Bypass Difficulty |
|---------|---------------|-------------------|
| Column-Level Access | Hard Guarantee | Impossible without KMS IAM compromise |
| Row-Level Security | Soft Control | Requires local root/memory debugging |
| Data Masking | Soft Control | Requires local root/memory debugging |
| Audit Telemetry | Soft Control | Requires local network tampering |

Use Holonomy to enable secure, lightweight local processing for trusted teams, while relying on your central KMS for absolute access revocation.
