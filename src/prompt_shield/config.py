"""
Configuration for Prompt Shield.

Allows fine-grained control over each layer's behavior and thresholds.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from prompt_shield.types import TrustLevel, RiskLevel


class TrustedFilterConfig(BaseModel):
    """Configuration for Layer 1: Trusted Content Filter."""
    
    enabled: bool = True
    
    # Trust level thresholds
    # Default to EXTERNAL to allow external contributors (common in OSS)
    # Set to REPORTER or higher for stricter environments
    minimum_trust_level: TrustLevel = TrustLevel.EXTERNAL
    allow_anonymous: bool = False
    allow_external: bool = True
    
    # Content type settings
    filter_issue_content: bool = True
    filter_comments: bool = True
    filter_file_content: bool = True
    filter_wiki_pages: bool = True
    
    # Allowlists/Blocklists
    allowed_users: List[str] = Field(default_factory=list)
    blocked_users: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)


class DataFilterConfig(BaseModel):
    """Configuration for Layer 2: DataFilter (Sanitization)."""
    
    enabled: bool = True
    
    # Sanitization mode
    mode: str = "remove"  # "remove", "mask", "escape", "tag"
    
    # Aggressiveness
    aggressiveness: str = "balanced"  # "minimal", "balanced", "aggressive"
    
    # What to sanitize
    remove_instructions: bool = True
    remove_code_blocks: bool = False  # Often legitimate
    remove_urls: bool = False  # Often legitimate, but check for exfil targets
    remove_email_addresses: bool = False
    
    # Preservation settings
    preserve_code_context: bool = True
    preserve_documentation: bool = True
    
    # Size limits
    max_content_length: int = 100000
    
    # Custom patterns to remove (regex)
    custom_removal_patterns: List[str] = Field(default_factory=list)


class DetectorConfig(BaseModel):
    """Configuration for Layer 3: Indirect Injection Detector."""
    
    enabled: bool = True
    
    # Detection thresholds
    confidence_threshold: float = 0.7
    min_risk_level: RiskLevel = RiskLevel.LOW
    
    # Detector components
    use_pattern_matching: bool = True
    use_ml_model: bool = True
    use_heuristics: bool = True
    
    # ML model settings
    ml_model_name: str = "microsoft/deberta-v3-base"
    ml_batch_size: int = 8
    ml_max_length: int = 512
    
    # Pattern matching settings
    pattern_confidence_boost: float = 0.2
    
    # Context awareness
    context_aware: bool = True  # Critical for indirect injection
    tool_output_sensitivity: float = 1.2  # Higher sensitivity for tool outputs
    
    # False positive control
    allow_code_instructions: bool = True
    allow_documentation_examples: bool = True
    
    # Custom patterns (name -> regex)
    custom_patterns: Dict[str, str] = Field(default_factory=dict)
    
    # Blocklist for known attack patterns
    blocked_patterns: List[str] = Field(default_factory=list)


class PromptFenceConfig(BaseModel):
    """Configuration for Layer 4: Prompt Fencing."""
    
    enabled: bool = True
    
    # Fence format
    fence_format: str = "xml"  # "xml", "markdown", "json", "delimiter"
    
    # Cryptographic settings
    use_signatures: bool = True
    signature_algorithm: str = "hmac-sha256"
    
    # Fence delimiters
    trusted_prefix: str = "<<<TRUSTED_CONTENT>>>"
    trusted_suffix: str = "<<<END_TRUSTED>>>"
    untrusted_prefix: str = "<<<UNTRUSTED_CONTENT source='{source}' trust='{trust}'>>>"
    untrusted_suffix: str = "<<<END_UNTRUSTED>>>"
    
    # Content tagging
    include_metadata: bool = True
    include_trust_level: bool = True
    include_source_type: bool = True


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    enabled: bool = True
    log_level: str = "INFO"
    log_detections: bool = True
    log_sanitizations: bool = True
    log_processing_times: bool = True
    
    # Sensitive data handling
    redact_content: bool = True
    max_logged_content_length: int = 200


class Config(BaseModel):
    """Master configuration for Prompt Shield."""
    
    # Layer configurations
    trusted_filter: TrustedFilterConfig = Field(default_factory=TrustedFilterConfig)
    data_filter: DataFilterConfig = Field(default_factory=DataFilterConfig)
    detector: DetectorConfig = Field(default_factory=DetectorConfig)
    prompt_fence: PromptFenceConfig = Field(default_factory=PromptFenceConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # Global settings
    fail_open: bool = False  # If True, allow content on processing errors
    strict_mode: bool = False  # If True, be more aggressive in blocking
    
    # Performance settings
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    max_concurrent_requests: int = 100
    request_timeout_seconds: float = 30.0
    
    # Default risk thresholds
    block_threshold: RiskLevel = RiskLevel.HIGH
    warn_threshold: RiskLevel = RiskLevel.MEDIUM
    
    @classmethod
    def default(cls) -> "Config":
        """Return default configuration."""
        return cls()
    
    @classmethod
    def strict(cls) -> "Config":
        """Return strict security configuration."""
        return cls(
            strict_mode=True,
            fail_open=False,
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.DEVELOPER,
                allow_anonymous=False,
                allow_external=False,
            ),
            data_filter=DataFilterConfig(
                aggressiveness="aggressive",
            ),
            detector=DetectorConfig(
                confidence_threshold=0.5,
                tool_output_sensitivity=1.5,
            ),
            block_threshold=RiskLevel.MEDIUM,
        )
    
    @classmethod
    def permissive(cls) -> "Config":
        """Return permissive configuration (more false positive tolerant)."""
        return cls(
            fail_open=True,
            trusted_filter=TrustedFilterConfig(
                allow_anonymous=True,
                allow_external=True,
            ),
            data_filter=DataFilterConfig(
                aggressiveness="minimal",
            ),
            detector=DetectorConfig(
                confidence_threshold=0.85,
                tool_output_sensitivity=1.0,
            ),
            block_threshold=RiskLevel.CRITICAL,
        )
