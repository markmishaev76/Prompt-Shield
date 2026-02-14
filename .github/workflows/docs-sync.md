---
on:
  push:
    branches: [main]

permissions:
  contents: read
  issues: read
  pull-requests: read

safe-outputs:
  create-pull-request:
    labels: [documentation, automated]

engine: claude

tools:
  github:
---

# Documentation Sync

Keep documentation aligned with code changes after pushes to main.

## Context

Prompt-Shield has documentation in several locations:
- `README.md` — Project overview, installation, usage, and feature list
- `docs/ARCHITECTURE.md` — System architecture and layer descriptions
- `docs/DESIGN.md` — Design decisions and rationale
- `docs/INTEGRATION.md` — Integration guides for GitHub Actions, GitLab, etc.
- `docs/QUICKSTART.md` — Getting started guide
- `examples/` — Usage examples

The core source code is in `src/prompt_shield/` with these key modules:
- `pipeline.py` — Main orchestration pipeline
- `patterns.py` — 65+ detection patterns
- `config.py` — Configuration models
- `layers/` — The 4 defense layers (trusted_filter, data_filter, detector, prompt_fence)
- `cli.py` — CLI interface
- `api.py` — FastAPI-based REST API

## Instructions

When code is pushed to main:

1. **Analyze the changes** in the push. Focus on changes to:
   - `src/prompt_shield/` — Core library changes
   - `action.yml` — GitHub Action definition changes
   - `Dockerfile` or `entrypoint.sh` — Container changes
   - `pyproject.toml` or `requirements.txt` — Dependency changes
   - `examples/` — Example code changes

2. **Compare against documentation** to find mismatches:
   - Are new features or configuration options documented?
   - Do architecture docs reflect structural changes?
   - Are new CLI commands or API endpoints documented?
   - Are new detection patterns mentioned in relevant docs?
   - Do examples still work with the current API?
   - Is the README's feature list accurate?

3. **If documentation updates are needed**, create a pull request with:
   - Updated documentation files that reflect the code changes
   - Clear, accurate descriptions matching the actual implementation
   - Consistent style with existing documentation

4. **If no updates are needed**, do nothing (don't create empty PRs).

## Guidelines

- Only update docs that genuinely need changes — don't rewrite for style
- Preserve existing documentation structure and formatting
- Be precise about technical details (function signatures, config options, etc.)
- Include code examples where they help clarify new features
- Keep the README concise; put detailed content in docs/ files
