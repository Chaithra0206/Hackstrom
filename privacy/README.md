# Privacy Filter (Module 1 / Upstream Sanitizer)

Fast, CPU-friendly, 100% in-memory privacy filter for images before they are transmitted to external AI agents or downstream gateways (Module 4).

## Core Capabilities

1. **EXIF & GPS Stripping**:
   - Analyzes incoming image buffers for EXIF/XMP/ICC metadata, explicitly targeting GPS IFD tag `0x8825`.
   - Strips 100% of metadata by clean raster copying into a fresh in-memory buffer.
   - Guarantees compatibility with downstream validators like `module4/app/image_validator.py` without triggering HTTP 422 errors.

2. **Face Detection & Semantic Masking**:
   - Offline, CPU-optimized Haar Cascade / OpenCV face detection (`privacy/app/assets/haarcascade_frontalface_default.xml`).
   - Redacts faces with configurable heavy Gaussian blur or blackout boxes.
   - Overlays semantic context badges (`[FACE_1]`, `[FACE_2]`) so multimodal models understand scene structure without identity exposure.

3. **Sensitive ID / PII Detection & Redaction**:
   - Powered by local ONNX Runtime OCR (`rapidocr-onnxruntime`).
   - Regex-based matching for sensitive identification:
     - **Aadhaar Numbers**: `\b\d{4}\s?\d{4}\s?\d{4}\b`
     - **PAN Numbers**: `\b[A-Z]{5}[0-9]{4}[A-Z]\b`
     - **Credit / Payment Cards**: `\b(?:\d[ -]*?){13,16}\b`
     - **Indian Phone Numbers**: `\b(?:\+91[\-\s]?)?[6-9]\d{9}\b`
     - **Email Addresses**
   - Applies solid black masking blocks labeled `[AADHAAR_REDACTED]`, `[PAN_REDACTED]`, `[ID_REDACTED]`, etc.

4. **100% In-Memory Guarantee**:
   - Zero temporary files, zero disk persistence.
   - All transformations occur strictly across `io.BytesIO` streams and NumPy ndarrays.

---

## Service Endpoints (Port 8001)

- `GET /api/sanitize/health` - Health and module status check.
- `POST /api/sanitize` - Ingests JSON Base64 image payload and options, returns sanitized Base64 image and audit report.
- `POST /api/sanitize/upload` - Ingests multipart file upload, returns sanitized PNG image directly with audit headers.
- `POST /api/sanitize/inspect` - Inspects image bytes for metadata, GPS tags, and dimensions without modifying pixels.

---

## Running the Service

### Prerequisites
```bash
pip install -r privacy/requirements.txt
```

### Launch Server
```bash
python -m uvicorn privacy.app.main:app --host 0.0.0.0 --port 8001 --reload
```

### Run Tests
```bash
pytest privacy/tests/test_privacy.py -v
```
