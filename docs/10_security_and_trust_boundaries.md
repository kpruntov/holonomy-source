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

## 2. Soft Controls (In-Memory Guardrails)

Once the KMS successfully unwraps the DEK, the data enters Holonomy's memory space. From this point forward, all governance is considered a **Soft Control**. 

### Row-Level Security (RLS) and Data Masking
RLS and data masking are evaluated *post-decryption* in the analyst's local RAM. 
- Holonomy evaluates the signed `holonomy_master_policy.json` manifest and applies filters or masking functions (like `REDACT` or `HASH`) before handing the data pointer to the Python environment.
- **The Limitation:** Because this happens on the client side (the analyst's machine), a malicious internal actor with administrative access to their machine could attach a memory debugger (like `gdb`), dump the RAM, or intercept the Rust process to extract the plaintext data before the mask is applied. 

These controls are designed as guardrails to prevent well-intentioned data scientists from accidentally viewing or leaking sensitive data, not to thwart malicious insiders with root access to the execution environment.

### Memory Isolation & Zero-Copy
Holonomy guarantees high performance by handing a native Apache Arrow memory pointer back to Python. This memory is not cryptographically isolated (e.g., via Intel SGX). Isolating it would require expensive serialization, destroying the zero-copy benefits.

### Telemetry & Audit Logging
Holonomy broadcasts access events to a centralized sink. Because this executes on the edge, a malicious user could manipulate their local firewall to block outbound HTTP requests to the telemetry server. Audit logging is a best-effort compliance trail.

## 3. Summary

| Feature | Boundary Type | Bypass Difficulty |
|---------|---------------|-------------------|
| Column-Level Access | Hard Guarantee | Impossible without KMS IAM compromise |
| Row-Level Security | Soft Control | Requires local root/memory debugging |
| Data Masking | Soft Control | Requires local root/memory debugging |
| Audit Telemetry | Soft Control | Requires local network tampering |

Use Holonomy to enable secure, lightweight local processing for trusted teams, while relying on your central KMS for absolute access revocation.
