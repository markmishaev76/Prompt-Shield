---
on:
  schedule: weekly on monday

permissions:
  contents: read
  issues: read
  pull-requests: read

safe-outputs:
  create-pull-request:
    labels: [testing, automated]

engine: claude

tools:
  github:
---

# Continuous Test Improvement

Weekly analysis of test coverage and quality, with PRs to improve testing.

## Context

Prompt-Shield has a test suite organized as:
- `tests/unit/` — Unit tests for individual layers and components
  - `test_data_filter.py`, `test_injection_detector.py`, `test_patterns.py`
  - `test_prompt_fence.py`, `test_trusted_filter.py`
- `tests/integration/` — Integration tests for layer combinations and pipeline
  - `test_layer_combinations.py`, `test_pipeline_integration.py`
- `tests/e2e/` — End-to-end tests for real-world scenarios
  - `test_real_world_attacks.py`, `test_gitlab_scenarios.py`
- `tests/test_detector.py`, `tests/test_pipeline.py` — Top-level tests
- `benchmarks/performance_benchmark.py` — Performance benchmarks

The core code under test is in `src/prompt_shield/` with:
- 4 defense layers in `layers/`
- 65+ detection patterns in `patterns.py`
- Pipeline orchestration in `pipeline.py`
- Configuration in `config.py`
- CLI in `cli.py` and API in `api.py`
- Enterprise features in `enterprise/`

## Instructions

Each week:

1. **Analyze current test coverage**:
   - Identify modules, functions, or code paths that lack tests
   - Look for edge cases not covered (e.g., unicode attacks, nested injections, boundary conditions)
   - Check if new patterns in `patterns.py` have corresponding test cases
   - Verify enterprise features have adequate test coverage

2. **Identify the highest-value test to add**. Prioritize:
   - Untested detection patterns (security-critical)
   - Edge cases in the pipeline (e.g., empty input, very large input, malformed content)
   - Layer interaction edge cases
   - CLI and API endpoint coverage
   - Configuration validation edge cases

3. **Create a focused PR** with:
   - One well-written test file or addition to an existing test file
   - Clear test names that describe what's being tested
   - Tests that follow the existing pytest patterns in the repo
   - A PR description explaining what coverage gap this addresses

## Guidelines

- Add 1 focused PR per week (quality over quantity)
- Follow the existing test style and conventions (pytest, fixtures in conftest.py)
- Tests should be deterministic and fast (no network calls, no flaky timing)
- Include both positive tests (should detect) and negative tests (should not false-positive)
- Use descriptive test names: `test_detector_catches_base64_encoded_injection`
