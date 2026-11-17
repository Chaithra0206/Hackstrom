# Module 4: Auto-Delete Proxy, Leak Blocker & API Gateway

Privacy-first API Gateway for dispatching sanitized user images to AI models (Gemini / OpenAI).

## Core Privacy Guarantees
1. **RAM-Only Execution**: Raw image bytes are never written to disk, SQLite, logs, or temp files.
2. **Buffer Zeroing**: Image data is held in mutable `bytearray` and securely overwritten with zeros in a mandatory `try/finally` block.
3. **Egress Firewall**: Strict domain whitelisting preventing unauthorized data leakage.
4. **Tamper-Evident Receipts**: Cryptographic deletion receipts and hash-chained audit logs verifying timely memory destruction.
