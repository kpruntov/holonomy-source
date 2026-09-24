<div align="center">
  <h1>Holonomy</h1>
  <p><strong>Local Data Governance for High-Performance Analytics</strong></p>

  <a href="https://pypi.org/project/holonomy/"><img alt="PyPI" src="https://img.shields.io/pypi/v/holonomy" /></a>
  <a href="https://github.com/kpruntov/holonomy/blob/master/LICENSE"><img alt="License: BSL" src="https://img.shields.io/badge/License-BSL-blue.svg" /></a>
  <a href="https://github.com/kpruntov/holonomy/tree/master/docs"><img alt="Docs" src="https://img.shields.io/badge/docs-read-green.svg" /></a>
</div>

Holonomy is a Data Governance tool designed specifically for local data processing. It enables Data Scientists and Engineers to run high-performance local analytics on highly sensitive enterprise data while strictly enforcing corporate access and data visibility policies. 

By integrating directly into your Python process, Holonomy decrypts, filters, and masks data locally in memory without requiring complex proxy servers or remote compute clusters.

**Supported Stack:**
- **Storage:** Local file systems and S3-compatible object storage (AWS S3, Cloudflare R2).
- **Format:** Exclusively supports Apache Parquet (leveraging Parquet Modular Encryption).
- **Compute:** Zero-copy integration with Polars, DuckDB, Pandas, and PyArrow.

## Features

- **Local Processing, Enterprise Compliance**: Safely pull encrypted datasets to your local machine. Holonomy evaluates centralized JSON Policy Manifests to dynamically enforce Row-Level Security (RLS) and Data Masking at read-time before the data ever reaches your DataFrame.
- **In-Process Execution (No Proxies)**: Forget deploying dedicated proxy servers, sidecars, or heavy compute clusters just for governance. Holonomy leverages your existing enterprise infrastructure (KMS, IdP, S3) and runs the actual decryption and policy filtering completely inside your application's Python process. Just run `pip install holonomy`.
- **Zero-Copy Performance**: Built on a highly concurrent Rust core and the Apache Arrow C Data Interface, Holonomy operates with true zero-copy semantics. The computational overhead for cryptographic validation and policy linting is practically invisible.
- **Zero-Knowledge Cryptography**: Data is protected at rest. In memory, your data is handled with extreme paranoia: cryptographic keys (DEKs) are forcefully wiped the moment they are no longer needed using the `ZeroizeOnDrop` pattern.

## Installation

Install via pip or uv:

```bash
pip install holonomy
# or
uv add holonomy
```

## Quick Start

Holonomy includes a zero-config local development mode. You can copy-paste this block and run it immediately without setting up any cloud infrastructure!

```python
import holonomy
import pyarrow as pa
import polars as pl

# 1. Initialize local dev mode (Mock KMS and Mock Identity)
holonomy.init(kms_provider="mock", policy_bucket="local", identity_provider="mock")

# 2. Create sensitive dummy data
batch = pa.RecordBatch.from_arrays(
    [pa.array([1, 2]), pa.array(["alice@test.com", "bob@test.com"])], 
    names=["id", "email"]
)

# 3. Securely write data (Locally encrypts with Parquet Modular Encryption)
contract = '{"name": "Users", "version": "1.0", "columns": [{"name": "id", "type": "int64", "required": true}, {"name": "email", "type": "string", "required": true}]}'
holonomy.write(
    batch=batch, 
    target="file:///tmp/users.parquet",
    purpose="data-engineering",
    contract_json=contract
)

# 4. Securely read data (Decrypts locally and dynamically enforces Data Masking)
arrow_data = holonomy.read(
    target="file:///tmp/users.parquet", 
    columns_to_read=["email"],
    purpose="data-science-analytics"
)

# 5. Zero-Copy transition directly into Polars!
df = pl.from_arrow(arrow_data)
print(df)
```

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- [1. Introduction & Core Concepts](docs/1_introduction_and_core_concepts.md)
- [2. Getting Started & Installation](docs/2_getting_started_and_installation.md)
- [3. Policy and Governance Engine](docs/3_policy_and_governance_engine.md)
- [4. Producer Path: Secure Data Ingestion](docs/4_producer_path_secure_data_ingestion.md)
- [5. Consumer Path: High Performance Analytics](docs/5_consumer_path_high_performance_analytics.md)
- [6. Advanced Features & Edge Case Handling](docs/6_advanced_features_and_edge_case_handling.md)
- [7. Infrastructure & Security Integrations](docs/7_infrastructure_and_security_integrations.md)
- [8. Troubleshooting, Safety & Best Practices](docs/8_troubleshooting_safety_and_best_practices.md)
- [9. Frequently Asked Questions](docs/9_frequently_asked_questions.md)

### Authoring Guides
- [Contract Authoring](docs/contract_authoring.md)
- [Policy Authoring](docs/policy_authoring.md)
- [CLI Reference](docs/cli_reference.md)

## License

Holonomy is licensed under the Business Source License (BSL). See the [LICENSE](LICENSE) file for more information.
