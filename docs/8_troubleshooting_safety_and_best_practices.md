# 8. Troubleshooting, Safety Guidelines & Best Practices

## 8.1. Performance Tuning
To get the absolute best performance out of Holonomy, you must understand how Parquet and Arrow interact with network constraints.

- **Column Pruning**: Never read the entire dataset if you don't need it. Always specify `columns_to_read` to heavily leverage HTTP Range Requests. Reading a 2MB column from a 10GB Parquet file takes milliseconds instead of minutes.
- **Memory Limits & 64-bit Offsets**: When dealing with extremely large string arrays or BLOB data over HTTP, you may hit 32-bit Arrow offset limits (`2GB` string size limits). Ensure your downstream tools are configured to accept `LargeBinaryArray` / `LargeStringArray` if processing gigantic unstructured columns.

## 8.2. Error Directory Reference
Holonomy intercepts low-level Rust panics and safely bubbles them up across the FFI boundary as standard Python exceptions (usually `PyRuntimeError`).

- **`InvalidParquet("No such file or directory")`**: Typically implies the dataset URI was mistyped, or the local environment credentials lack sufficient IAM permissions to list the S3 object.
- **`Signature invalid`**: Emitted when Holonomy attempts to read a `holonomy_master_policy.json` that has been tampered with locally, or signed by an untrusted public key.
- **`Configuration has already been initialized`**: Occurs if `holonomy.init()` is called multiple times within the same Python process.

## 8.3. Cryptographic Memory Purging (`ZeroizeOnDrop`)
Holonomy was designed under the assumption that the host machine running the analytics process might be compromised or might crash and leave memory dumps behind.

All sensitive in-memory assets (such as the `ResolvedKmsConfig` endpoint URLs, and most critically, the raw plaintext DEKs stored in the `DekCache`) are wrapped in the `Zeroize` and `ZeroizeOnDrop` traits. 
- The moment a variable goes out of scope, or the moment a Python script crashes and the Rust runtime initiates cleanup, the OS memory allocations holding those secrets are actively overwritten with zeroes before they are released back to the operating system.
- This effectively prevents cold-boot attacks and post-crash memory forensics from exposing your Data Encryption Keys.
