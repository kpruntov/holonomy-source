# Cookbook: Data Science on Corporate Laptops

Modern data science requires rapid iteration. Analysts often want to pull subsets of data locally to their corporate laptops to train models using Jupyter Notebooks and Pandas/Polars. However, allowing encrypted data and KMS decryption keys onto end-user hardware introduces significant security risks.

## The Challenge
If you grant an analyst access to KMS, their local machine becomes a cryptographic endpoint. If their laptop is compromised, or if they accidentally commit a Jupyter notebook with a crash dump, raw Data Encryption Keys (DEKs) could leak. You must balance the developer experience of local execution with the reality of endpoint security.

## The Holonomy Solution: Ephemeral Contexts & Memory Wiping
Holonomy was built specifically for this "Local Analysis" use-case. It uses a combination of dynamic identity validation and active memory zeroization (`ZeroizeOnDrop`) to ensure that DEKs only exist in RAM for the microsecond they are actively decrypting data.

### The Execution
Instead of distributing static API keys, you integrate Holonomy with your corporate Identity Provider (IdP) using OIDC. The analyst runs a command to fetch a short-lived, 15-minute token.

```python
import holonomy
import polars as pl
import os

# The analyst authenticates via SSO (e.g., Okta/Google)
# and injects the ephemeral token into the environment.
os.environ["HOLONOMY_CREDENTIAL_FILE"] = "/tmp/ephemeral_oidc_token.jwt"

# Holonomy reads the token, assumes the role, and fetches the DEK.
# The DEK is held in RAM, the Parquet file is streamed, and the DEK
# is instantly zeroized from memory when the read is complete.
table = holonomy.read("s3://data-lake/financial_data.parquet")
df = pl.from_arrow(table)
```

## 💡 Infrastructure & Endpoint Tips for Laptop Security
To safely deploy this architecture, you must lock down the analyst's endpoint.

- **No Local Admin Rights:** Analysts should never have `root` or `Administrator` privileges on their corporate laptops. Without root, malware (or a malicious insider) cannot attach `gdb` or memory profilers to the Python process to extract the DEKs while Holonomy is running.
- **Short-Lived Sessions:** Configure your IdP to issue tokens with a maximum lifespan of 15-30 minutes. If a laptop is stolen, the token becomes useless before an attacker can realistically bypass disk encryption.
- **Block Core Dumps:** Ensure your corporate MDM (Mobile Device Management) pushes policies that disable core dumps (`ulimit -c 0`). If Jupyter crashes while analyzing sensitive rows, the OS must not write a snapshot of the RAM to the physical hard drive.
- **Disable Swap/Pagefile (Optional but Recommended):** For highly sensitive environments, disable OS memory swapping on analyst laptops. This guarantees that unencrypted Arrow buffers are never accidentally paged to the SSD.
