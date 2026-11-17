# Module 4 Integration Guide: Auto-Delete Proxy, Leak Blocker & API Gateway

Module 4 serves as the secure, RAM-only API Gateway bridging upstream sanitization pipelines with downstream AI providers (Gemini & OpenAI). It guarantees in-memory retention, egress firewalls, verifiable memory zeroing, and tamper-evident audit logging.

---

## 1. Upstream Contract: Input from Module 3 (Local Privacy Filter)

Module 3 is the local, client-side privacy engine responsible for:
- Blurring faces and personally identifiable credentials.
- Stripping all GPS and location tags.

### Ingestion Contract
Module 3 dispatches data to Module 4 via `POST /v1/sessions` as a multipart form payload:
- **`file`**: Sanitized image bytes (`JPEG`, `PNG`, or `WEBP`).
- **`task`**: User task instructions (e.g. `"Describe the objects"`).

### Upstream Enforcement & Rejection Rules
Module 4 enforces strict verification in RAM before creating a session:
1. **EXIF GPS Detection (HTTP 422)**:
   Module 4 scans raw APP1 and TIFF IFD0 blocks for GPS tag `0x8825`. If GPS coordinates remain present, the request is aborted with:
   ```json
   {
     "detail": "Image contains EXIF GPS metadata. Please run the local privacy filter first."
   }
   ```
2. **Size Enforcement (HTTP 413)**:
   Streaming chunks are monitored; uploads exceeding `MAX_IMAGE_MB` (default 10MB) are aborted immediately.
3. **Magic Byte Verification (HTTP 400)**:
   Only verified JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), and WEBP (`RIFF....WEBP`) magic headers are permitted regardless of declared MIME headers.

---

## 2. API Endpoints Specification

### 2.1 POST `/v1/sessions`
Initializes a RAM-only `SecureImageBuffer` session with an expiration TTL (`SESSION_TTL_SECONDS`).

- **Request**: Multipart Form Data
  - `file`: Raw image bytes
  - `task`: Task prompt string
- **Success Response (201 Created)**:
  ```json
  {
    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
    "image_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "expires_in": 120
  }
  ```
- **Error Codes**:
  - `400 Bad Request`: Empty image or invalid magic bytes.
  - `413 Content Too Large`: Exceeds `MAX_IMAGE_MB`.
  - `422 Unprocessable Content`: Unsanitized image containing EXIF GPS.

---

### 2.2 POST `/v1/sessions/{session_id}/run`
Executes an AI task against the in-memory buffer. Enforces egress filtering, calls allowlisted tools, zeroes buffer RAM in `finally:`, and generates a deletion receipt.

- **Request**: JSON
  ```json
  {
    "provider": "gemini",
    "task_override": "Extract any visible numbers."
  }
  ```
- **Success Response (200 OK)**:
  ```json
  {
    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
    "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
    "answer": "Detected invoice number: 4092.",
    "tool_calls": []
  }
  ```
- **Error Codes**:
  - `403 Forbidden`: Blocked by `EgressFirewall` (prompt injection, egress URL leak, base64 blob, etc.).
  - `404 Not Found`: Session does not exist or expired via TTL.

---

### 2.3 GET `/v1/receipts/{session_id}`
Retrieves the cryptographically signed deletion receipt attesting that memory was zeroed.

- **Response (200 OK)**:
  ```json
  {
    "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
    "image_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "bytes_wiped": 2048,
    "wipe_method": "bytearray ctypes.memset zero-fill",
    "wipe_verified": true,
    "status": "completed",
    "issued_utc": "2026-11-18T00:00:00.000000+00:00",
    "scope": "in_memory_gateway_destruction",
    "limitations": "Attests only that this gateway's in-memory copy was zero-filled. It cannot attest to retention by the third-party AI provider.",
    "signature": "8f56a312bc815b39e2467d363b925bdfa91b2df9cc01a3cfb578c736e4f323a1"
  }
  ```
- **Error Codes**:
  - `404 Not Found`: No receipt found for the specified session ID.

---

### 2.4 POST `/v1/receipts/verify`
Validates the HMAC-SHA256 signature of a receipt against canonical JSON reconstruction.

- **Request**: Full deletion receipt JSON
- **Response (200 OK)**:
  ```json
  {
    "valid": true
  }
  ```

---

### 2.5 GET `/v1/audit?session_id=&limit=`
Queries the hash-chained audit log with raw payload details redacted.

- **Query Parameters**:
  - `session_id` (optional): Filter events for a specific session.
  - `limit` (default: 50, max: 500): Event count ceiling.
- **Response (200 OK)**:
  ```json
  [
    {
      "id": 1,
      "ts_utc": "2026-11-18T00:00:00.000000+00:00",
      "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
      "event_type": "image_wiped",
      "prev_hash": "9ff2fdaec5850ca0a7f4a3744f624959bb63a89472498df773e6f5df3200b8e2",
      "entry_hash": "d0db22ba2c41ab731158b7eda05d76a7586dd83d4aec22bd864d966a1a36cd80"
    }
  ]
  ```

---

### 2.6 GET `/v1/audit/verify`
Validates the cryptographic integrity of the entire audit chain from genesis to head.

- **Response (200 OK)**:
  ```json
  {
    "chain_intact": true,
    "first_broken_index": null
  }
  ```
- **Response on Tampering Detected**:
  ```json
  {
    "chain_intact": false,
    "first_broken_index": 4
  }
  ```

---

## 3. End-to-End Sample `curl` Flow

### Step 1: Create In-Memory Session
```bash
curl -X POST http://localhost:8000/v1/sessions \
  -F "file=@sanitized_image.jpg;type=image/jpeg" \
  -F "task=Summarize the visible text in this document"
```
*Response*:
```json
{"session_id":"w9Z7B8qR3vT1mK4L7nQ2zA","image_sha256":"e3b0c44...","expires_in":120}
```

### Step 2: Run AI Model Task
```bash
curl -X POST http://localhost:8000/v1/sessions/w9Z7B8qR3vT1mK4L7nQ2zA/run \
  -H "Content-Type: application/json" \
  -d '{"provider": "gemini"}'
```
*Response*:
```json
{
  "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
  "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
  "answer": "Document contains a privacy disclosure.",
  "tool_calls": []
}
```

### Step 3: Retrieve Deletion Receipt
```bash
curl -X GET http://localhost:8000/v1/receipts/w9Z7B8qR3vT1mK4L7nQ2zA
```
*Response*: Signed JSON receipt attesting to 0x00 memory wipe.

### Step 4: Cryptographically Verify Deletion Receipt
```bash
curl -X POST http://localhost:8000/v1/receipts/verify \
  -H "Content-Type: application/json" \
  -d '{
    "bytes_wiped": 2048,
    "image_sha256": "e3b0c44...",
    "issued_utc": "2026-11-18T00:00:00.000000+00:00",
    "limitations": "Attests only that this gateway'\''s in-memory copy was zero-filled. It cannot attest to retention by the third-party AI provider.",
    "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
    "scope": "in_memory_gateway_destruction",
    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
    "status": "completed",
    "wipe_method": "bytearray ctypes.memset zero-fill",
    "wipe_verified": true,
    "signature": "8f56a312bc815b39e2467d363b925bdfa91b2df9cc01a3cfb578c736e4f323a1"
  }'
```
*Response*:
```json
{"valid": true}
```

### Step 5: Verify Hash-Chained Audit Log
```bash
curl -X GET http://localhost:8000/v1/audit/verify
```
*Response*:
```json
{"chain_intact": true, "first_broken_index": null}
```
