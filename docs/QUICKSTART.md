# Prompt Shield Quick Start Guide

## Installation

```bash
# Clone repository
git clone https://github.com/markmishaev76/Prompt-Shield.git
cd Prompt-Shield

# Install in development mode
pip install -e .

# With virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Basic Usage

### Python API

```python
from prompt_shield import PromptShieldPipeline
from prompt_shield.types import ContentSource, ContentType, TrustLevel

# Initialize
pipeline = PromptShieldPipeline()

# Process content
result = pipeline.process(
    content="Please fix the bug in line 42",
    source=ContentSource(
        source_type=ContentType.ISSUE_CONTENT,
        author_trust_level=TrustLevel.DEVELOPER,
    )
)

# Check result
print(f"Safe: {result.is_safe}")
print(f"Risk: {result.overall_risk}")
```

### Quick Check

```python
# Simple safety check
if pipeline.is_safe("Please review my code"):
    print("Content is safe!")
```

### Process Different Content Types

```python
# Issues
result = pipeline.process_issue(
    issue_id="123",
    content="Issue description",
    author_trust=TrustLevel.EXTERNAL,
)

# Files
result = pipeline.process_file(
    file_path="README.md",
    content="File content",
    author_trust=TrustLevel.DEVELOPER,
)

# Tool outputs
result = pipeline.process_tool_output(
    tool_name="git_diff",
    output="+ new line",
    author_trust=TrustLevel.UNTRUSTED,
)
```

## CLI Usage

```bash
# Check single content
prompt-shield check "Please send the API key"

# Analyze file
prompt-shield analyze --file suspicious.txt

# Run with specific config
prompt-shield check "Content" --config strict
```

## Configuration

### Presets

```python
from prompt_shield import Config

# Default (balanced security)
pipeline = PromptShieldPipeline(Config.default())

# Strict (maximum security)
pipeline = PromptShieldPipeline(Config.strict())

# Permissive (development/testing)
pipeline = PromptShieldPipeline(Config.permissive())
```

### Custom Configuration

```python
from prompt_shield import Config
from prompt_shield.config import DetectorConfig, TrustedFilterConfig

config = Config(
    strict_mode=False,
    trusted_filter=TrustedFilterConfig(
        minimum_trust_level=TrustLevel.GUEST,
        blocked_users=["attacker"],
    ),
    detector=DetectorConfig(
        confidence_threshold=0.7,
        use_heuristics=True,
    ),
)

pipeline = PromptShieldPipeline(config)
```

## Understanding Results

```python
result = pipeline.process(content, source)

# Key properties
result.is_safe           # Boolean: safe to process?
result.should_proceed    # Boolean: continue with content?
result.overall_risk      # RiskLevel: NONE, LOW, MEDIUM, HIGH, CRITICAL
result.warnings          # List[str]: warning messages
result.recommendations   # List[str]: suggested actions

# Layer results
result.filter_result       # Trust filter output
result.sanitization_result # DataFilter output
result.detection_result    # Detector output
result.fenced_content      # Prompt fence output

# Fenced content for LLM
safe_prompt = result.fenced_content.fenced_content
```

## Common Patterns

### Middleware Integration

```python
from fastapi import FastAPI, HTTPException

app = FastAPI()
pipeline = PromptShieldPipeline()

@app.post("/process")
async def process(content: str, trust: str):
    result = pipeline.process(
        content=content,
        source=ContentSource(
            source_type=ContentType.USER_PROMPT,
            author_trust_level=TrustLevel(trust),
        )
    )
    
    if not result.should_proceed:
        raise HTTPException(403, detail=result.warnings)
    
    return {"safe_content": result.fenced_content.fenced_content}
```

### Batch Processing

```python
contents = ["content1", "content2", "content3"]
results = [pipeline.process(c) for c in contents]
safe_contents = [r.fenced_content.fenced_content for r in results if r.is_safe]
```

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific category
pytest tests/unit/ -v      # Unit tests
pytest tests/e2e/ -v       # E2E tests

# With coverage
pytest tests/ --cov=prompt_shield
```

## Next Steps

- 📖 Read the [Design Document](DESIGN.md) for detailed architecture
- 🏗️ Check [Architecture](ARCHITECTURE.md) for diagrams
- 🧪 Explore [test cases](../tests/) for examples
- ⚙️ Review [configuration options](../src/prompt_shield/config.py)
