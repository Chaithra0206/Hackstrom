# AGENTS.md

## Project

- Hackathon project: **Dual-Layer Photo & AI Agent Privacy Shield**.
- Module 1 scope: Local Privacy Filter (Upstream Sanitizer) - EXIF/GPS stripping, face blurring/masking, sensitive PII/ID OCR redaction (Aadhaar, PAN, Cards, Phones, Emails).
- Module 2 scope: Anti-AI Cloning Shield using adversarial cloaking (PGD/FGSM) with CLIP/ResNet and DWT-SVD watermarking.
- Module 4 scope: Auto-Delete Proxy, Leak Blocker & API Gateway for safe multimodal AI agent interactions.
- Frontend scope: Next.js UI uniting the Social Protection and Safe AI Agent tabs.
- Pipeline order is mandatory: cloaking first, then DWT-SVD watermark (Member 2).
- **Do not reorder the pipeline. Cloaking runs before watermarking.**
- **Use in-memory processing only; do not write uploaded images to disk.**

## Repository layout

The repository is structured as follows:

- `README.md` — Project architecture, module descriptions, and quick-start guide.
- `AGENTS.md` — Agent instructions, constraints, and project layout reference.
- `.gitignore` — Ignore rules for Python cache, virtual environments, and temporary artifacts.
- `privacy/` — **Module 1 (Local Privacy Filter / Upstream Sanitizer)**:
  - `privacy/app/main.py` — FastAPI application on port 8001 with CORS configuration.
  - `privacy/app/router.py` — Endpoints: `/api/sanitize`, `/api/sanitize/upload`, `/api/sanitize/inspect`, `/api/sanitize/health`.
  - `privacy/app/schemas.py` — Pydantic request/response and audit report schemas.
  - `privacy/app/pipeline.py` — Pure in-memory orchestration pipeline.
  - `privacy/app/exif_stripper.py` — Detection and stripping of EXIF, GPS tag `0x8825`, XMP, and ICC metadata.
  - `privacy/app/face_redactor.py` — Fast offline face detection, Gaussian blur/blackout, and semantic badges (`[FACE_1]`).
  - `privacy/app/pii_redactor.py` — Local CPU RapidOCR engine and regex matching for Aadhaar, PAN, Cards, Phones, and Emails.
  - `privacy/app/assets/` — Offline OpenCV Haar cascade weights (`haarcascade_frontalface_default.xml`).
  - `privacy/requirements.txt` — Python dependencies for Module 1.
  - `privacy/tests/test_privacy.py` — Unit test suite verifying EXIF purge, Module 4 compatibility, and PII masking.
- `app/` — **Module 2 (Anti-AI Cloning & Watermark)**:
  - PGD/FGSM adversarial cloaking, face detection engine, and DWT-SVD fragile watermarking.
- `module4/` — **Module 4 (API Gateway & Leak Blocker)**:
  - RAM-only image proxy, magic byte / EXIF GPS validator, egress firewall, and deletion receipts.
- `frontend/` — **Frontend UI**:
  - Next.js / Tailwind CSS dashboard communicating with Module 1, Module 2, and Module 4.

## Commands

- **Module 1 (Privacy Filter)**:
  - Install dependencies: `pip install -r privacy/requirements.txt`
  - Run server: `python -m uvicorn privacy.app.main:app --port 8001 --reload`
  - Run tests: `pytest privacy/tests/test_privacy.py -v`
- **Module 2 (Cloaking & Watermark)**:
  - Run server: `python -m uvicorn app.main:app --port 8000 --reload`
- **Frontend**:
  - Install dependencies: `npm --prefix frontend install`
  - Run dev server: `npm --prefix frontend run dev`

## Coding conventions

- Preserve the cloaking → DWT-SVD watermark pipeline boundary and pass image data in memory.
- Keep Module 2 code focused on PGD/FGSM cloaking and its CLIP/ResNet integrations.
- Keep Module 1 code focused on in-memory EXIF stripping, face blurring, and PII/ID redaction.
- Guarantee that all outputs from Module 1 pass `module4/app/image_validator.py` without triggering HTTP 422 (EXIF GPS tag `0x8825` must be completely absent).
- Add tests for new behavior and keep transformations deterministic/configurable where practical.
- Avoid writing uploaded or intermediate images to disk; use in-memory buffers/arrays exclusively.
- Keep changes small, documented, and consistent with the surrounding code.
