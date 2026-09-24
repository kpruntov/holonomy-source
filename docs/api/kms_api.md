# Remote KMS Interface (AWS KMS / HashiCorp Vault Proxy)

This describes the expected API contract for the SDK to communicate with the corporate Key Management Service.

## Endpoints

### `POST /kms/decrypt`
Decrypts the Parquet Modular Encryption (PME) DEK metadata.

**Request Payload:**
*   `encrypted_dek` (bytes): The sealed key from the Parquet footer.
*   `environment_context` (object):
    *   `client_ip` (string)
    *   `timezone` (string)
    *   `mdm_posture_token` (string)
    *   `device_cert` (string)

**Response Payload:**
*   `plaintext_dek` (bytes): The 256-bit AES key.
*   `status` (string): "Approved" or "Denied".

### `DELETE /kms/keys/{partition_id}`
Permanently deletes the DEK associated with a micro-partition for crypto-shredding.

**Request Payload:**
*   `admin_token` (string): High-privilege authentication token.

**Response:** HTTP 204 No Content.