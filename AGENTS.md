# AGENTS.md

## Project

- Hackathon project: **Dual-Layer Photo & AI Agent Privacy Shield**.
- Module 2 scope: Anti-AI Cloning Shield using adversarial cloaking (PGD/FGSM) with CLIP/ResNet.
- Pipeline order is mandatory: cloaking first, then DWT-SVD watermark (Member 2).
- **Do not reorder the pipeline. Cloaking runs before watermarking.**
- **Use in-memory processing only; do not write uploaded images to disk.**

## Repository layout

The checkout currently contains:

- `README.md` — project title only.
- `.gitignore` — Node/frontend-oriented ignore rules.
- `AGENTS.md` — instructions for coding agents.

Add new source and tests in clearly named directories when implementation files are introduced; update this section with the actual layout.

## Commands

No install, test, lint, or typecheck command is currently defined: this checkout has no `package.json`, Python packaging/configuration file, Makefile, or test/lint/typecheck configuration. Do not invent commands; update this section after adding the relevant project files.

## Coding conventions

- Preserve the cloaking → DWT-SVD watermark pipeline boundary and pass image data in memory.
- Keep Module 2 code focused on PGD/FGSM cloaking and its CLIP/ResNet integrations.
- Add tests for new behavior and keep transformations deterministic/configurable where practical.
- Avoid writing uploaded or intermediate images to disk; use in-memory buffers/arrays.
- Keep changes small, documented, and consistent with the surrounding code once source is present.
