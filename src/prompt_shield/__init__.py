"""
Prompt Shield - Multi-layered defense against indirect prompt injection attacks.

This library provides a comprehensive solution for detecting and mitigating
prompt injection attacks, with a special focus on INDIRECT prompt injections
that occur through tool outputs (issues, files, comments, etc.).

Architecture:
    Layer 1: Trusted Content Filter - Filter by author permissions
    Layer 2: DataFilter - Sanitize/remove malicious instructions from content
    Layer 3: Indirect Injection Detector - ML + pattern-based detection
    Layer 4: Prompt Fencing - Cryptographic tagging of trusted vs untrusted content
"""

from prompt_shield.types import (
    ContentSource,
    ContentType,
    DetectionResult,
    FilterResult,
    SanitizationResult,
    TrustLevel,
    FencedContent,
)
from prompt_shield.pipeline import PromptShieldPipeline
from prompt_shield.config import Config

__version__ = "0.1.0"
__all__ = [
    "PromptShieldPipeline",
    "Config",
    "ContentSource",
    "ContentType",
    "DetectionResult",
    "FilterResult",
    "SanitizationResult",
    "TrustLevel",
    "FencedContent",
]
