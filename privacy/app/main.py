"""
Local Privacy Filter (Module 1 / Upstream Sanitizer)
FastAPI Application Entrypoint
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Runs on port 8001 by default (complementing Module 2 on 8000 and Next.js on 3000).
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from privacy.app.router import router as sanitize_router

app = FastAPI(
    title="Local Privacy Filter (Module 1)",
    description=(
        "In-Memory Upstream Sanitizer: Purges EXIF & GPS metadata (tag 0x8825), "
        "applies face redaction with semantic tags ([FACE_1]), and blacks out "
        "sensitive PII (Aadhaar, PAN, Cards, Phone, Email) via local CPU OCR."
    ),
    version="1.0.0",
)

# Configure CORS for Next.js frontend (http://localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sanitize_router)


@app.get("/")
def root():
    return {
        "service": "Local Privacy Filter",
        "module": "Module 1 (Upstream Sanitizer)",
        "status": "online",
        "endpoints": {
            "health": "/api/sanitize/health",
            "sanitize": "/api/sanitize",
            "upload": "/api/sanitize/upload",
            "inspect": "/api/sanitize/inspect",
            "docs": "/docs",
        },
        "downstream_contract": {
            "target": "Module 4 (Auto-Delete API Gateway)",
            "guarantees": [
                "Zero disk writes (RAM only)",
                "EXIF GPS tag 0x8825 stripped (Passes Module 4 HTTP 422 check)",
                "Valid magic bytes preserved (JPEG/PNG)",
            ],
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("privacy.app.main:app", host="127.0.0.1", port=8001, reload=True)
