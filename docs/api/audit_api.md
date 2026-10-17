# Audit Telemetry Sink API

This asynchronous API receives non-blocking telemetry events from the Holonomy runtime.

## Endpoints

### `POST /audit/events`
Records a data access or write event.

**Request Payload (JSON):**
*   `timestamp` (ISO8601 string): Time of execution.
*   `user_hash` (string): Anonymized identifier of the executing user.
*   `file_signature` (string): SHA256 or S3 ETag of the accessed dataset.
*   `accessed_columns` (list of strings): The specific columns requested/processed.
*   `business_purpose` (string): The mandatory purpose provided by the user.
*   `action` (string): "READ", "WRITE", or "SHRED".
*   `geofence_status` (string): "PASS" or "VIOLATION".

**Response:** HTTP 202 Accepted.