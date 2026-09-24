# Holonomy CLI Reference

The `holonomy inspect` CLI is a powerful DevOps and Platform Engineering tool bundled automatically when you install the Holonomy Python wheel. It is designed to safely interact with massive remote datasets, perform structural schema extraction, detect drift, and scaffold JSON Data Contracts—without ever downloading full multi-gigabyte Parquet files.

## 1. Remote Data Inspection
You can point the CLI directly at cloud storage URIs.
Holonomy natively supports both AWS S3 and Cloudflare R2 object storage routing.

```bash
# Inspecting an AWS S3 bucket
holonomy inspect s3://my-bucket/dataset-v1/

# Inspecting a Cloudflare R2 bucket
holonomy inspect r2://my-cloudflare-bucket/dataset-v1/
```

### AWS / R2 Authentication (SigV4)
The `inspect` command utilizes the official `aws-sdk-s3` Rust crate, enabling full support for authenticated Range requests against private buckets.
To authenticate, you must set standard AWS environment variables (or load them from an `.env` file):
- `AWS_ACCESS_KEY_ID`: Your AWS or Cloudflare R2 Access Key
- `AWS_SECRET_ACCESS_KEY`: Your AWS or Cloudflare R2 Secret Key
- `AWS_ENDPOINT_URL`: For R2, this MUST be set to your account's R2 endpoint (e.g., `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`)
- `AWS_REGION`: Defaults to `auto` or `us-east-1` depending on the provider

### Automatic Directory Traversal & Schema Drift Detection
If you point `holonomy inspect` at a *directory* instead of a single file, the tool intelligently behaves as a drift detector:
1. It lists the directory contents.
2. It randomly samples up to **50 Parquet files** from the partition tree.
3. It downloads the Parquet metadata footers for each of the 50 files.
4. It compares the structural schema across all sampled files to ensure absolute homogeneity.

If `part-001.parquet` contains a different column layout or type structure than `part-002.parquet`, the CLI will aggressively warn you of structural mutations (Schema Drift) before you attempt to ingest or rely on the data in a downstream pipeline.

## 2. Generating Baseline Data Contracts (`--generate-contract` / `-g`)
Instead of manually mapping columns by hand to build a `DataContract` for the `holonomy.write()` validator, you can instruct the CLI to automatically build a baseline JSON Data Contract directly from the physical reality of the Parquet footers.

```bash
holonomy inspect s3://my-bucket/dataset/ --generate-contract --output contract.json
```
*(Aliases: `-g` for generate, `-o` for output)*

### What happens under the hood?
1. The CLI reads the physical and logical Arrow types from the remote metadata.
2. It maps the physical types to their string equivalents required by the `Validator` struct (e.g., `INT32` -> `"int32"`, `BYTE_ARRAY` -> `"string"`).
3. It scaffolds a valid `DataContract` JSON document (containing `name`, `version`, and the `columns` array).

You can then pass this `contract.json` into the `holonomy.write()` API to guarantee your structural edge constraints perfectly match the shape of the existing data on S3.

## 3. Policy Management (`holonomy policy`)
The CLI provides tooling for generating and verifying cryptographic Policy Manifests. Policies manage Data Governance, Role-Based Access Control (RBAC), and Data Masking.

### Creating Policy Templates & Dummy Policies
You can generate an unsigned policy template (the raw JSON payload) to serve as a starting point for authoring your own governance policies:
```bash
holonomy policy --create-template -o template.json
```

**Date & Timestamp Filtering Note:** When authoring row filters in your template (e.g., `join_date > '2025-01-01'`), the governance engine automatically supports standard ISO 8601 / RFC 3339 datetime strings, as well as custom format `dd-mm-yyyyThh:mm:ss:MMM`. It will dynamically parse these strings and evaluate them accurately against underlying Arrow `Date32`, `Date64`, or `Timestamp` columns.

For testing purposes, you can also generate a mock signed `PolicyEnvelope`:
```bash
holonomy policy --create-dummy
```
*Note: The `--create-dummy` command outputs both the signed `PolicyEnvelope` and the corresponding Public Key (Hex) needed to verify it.*

### Verifying a Policy
You can verify the cryptographic integrity of a generated Policy Envelope:
```bash
holonomy verify <path/to/policy.json> <public_key_hex> [--signature <signature_hex>]
```
If the policy file is a JSON `PolicyEnvelope` containing a `.signature` field, the `--signature` argument is entirely optional, drastically improving DX.

## 4. Authentication (`holonomy auth`)
To interact with centralized services or run commands that require identity (e.g., pulling policies), you can authenticate via the OIDC Device Authorization Flow.

```bash
holonomy auth login
```
This will securely authenticate your CLI session and save the credentials locally.

## 5. Cryptographic Signing (`holonomy sign`)
Before a Policy Manifest can be distributed or uploaded to the centralized Policy Bucket, it must be cryptographically signed using an Ed25519 Private Key.

```bash
# Sign a manifest with a specific private key
holonomy sign <path/to/manifest.json> --key <private_key_hex> --out signed_envelope.json

# Generate a new random keypair and sign the manifest
holonomy sign <path/to/manifest.json> --out signed_envelope.json
```
If you omit the `--key` argument, the CLI will automatically generate a secure Ed25519 key pair, use it to sign the manifest, and print the new private key to the console for you to save securely.

## 6. Contract Management (`holonomy contract`)
*Coming Soon (Task-080)*

### Publishing Contracts
Instead of manually calculating Base64-encoded strings for target URIs, you will be able to seamlessly push local Data Contracts to the centralized Policy Bucket:
```bash
holonomy contract publish --target s3://data-lake/sales/dataset.parquet --file local_contract.json
```
The CLI will handle translating the target to the correct `base64_url_safe(target) + .json` format expected by the backend engine.
