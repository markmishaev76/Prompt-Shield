"""
Core type definitions for Prompt Shield.

These types model the data flowing through the multi-layered defense system,
with particular attention to the context needed for indirect injection detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContentType(str, Enum):
    """Type of content being processed - critical for context-aware detection."""
    
    # Direct user input (traditional prompt injection target)
    USER_PROMPT = "user_prompt"
    
    # Tool outputs - PRIMARY TARGET for indirect injection
    TOOL_OUTPUT = "tool_output"
    ISSUE_CONTENT = "issue_content"
    ISSUE_COMMENT = "issue_comment"
    FILE_CONTENT = "file_content"
    CODE_SNIPPET = "code_snippet"
    MERGE_REQUEST = "merge_request"
    COMMIT_MESSAGE = "commit_message"
    WIKI_PAGE = "wiki_page"
    PIPELINE_LOG = "pipeline_log"
    
    # System-generated content (generally trusted)
    SYSTEM_MESSAGE = "system_message"
    API_RESPONSE = "api_response"
    
    # Unknown/other
    UNKNOWN = "unknown"


class TrustLevel(str, Enum):
    """Trust level of content source."""
    
    SYSTEM = "system"           # System-generated, fully trusted
    ADMIN = "admin"             # Admin/owner, highly trusted
    MAINTAINER = "maintainer"   # Maintainer, trusted
    DEVELOPER = "developer"     # Developer with write access
    REPORTER = "reporter"       # Can create issues but limited access
    GUEST = "guest"             # Guest access
    EXTERNAL = "external"       # External contributor
    ANONYMOUS = "anonymous"     # Anonymous/unknown, untrusted
    UNTRUSTED = "untrusted"     # Explicitly untrusted


class RiskLevel(str, Enum):
    """Risk level classification."""
    
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    """Type of detected prompt injection attack."""
    
    # Direct injection types
    DIRECT_JAILBREAK = "direct_jailbreak"
    SYSTEM_PROMPT_OVERRIDE = "system_prompt_override"
    ROLE_IMPERSONATION = "role_impersonation"
    
    # Indirect injection types - OUR PRIMARY FOCUS
    INDIRECT_INSTRUCTION = "indirect_instruction"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    ACTION_STEERING = "action_steering"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_CODE_INJECTION = "malicious_code_injection"
    SOCIAL_ENGINEERING = "social_engineering"
    
    # Subtle attacks
    SUBTLE_STEERING = "subtle_steering"
    CONTEXT_MANIPULATION = "context_manipulation"
    INSTRUCTION_SMUGGLING = "instruction_smuggling"
    
    # Unknown
    UNKNOWN = "unknown"


class ContentSource(BaseModel):
    """Metadata about the source of content - critical for trust assessment."""
    
    # Source identification
    source_type: ContentType = ContentType.UNKNOWN
    source_id: Optional[str] = None  # e.g., issue ID, file path
    source_url: Optional[str] = None
    
    # Author information
    author_id: Optional[str] = None
    author_username: Optional[str] = None
    author_email: Optional[str] = None
    author_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    
    # Temporal information
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    # Additional context
    project_id: Optional[str] = None
    project_path: Optional[str] = None
    is_internal: bool = False
    is_verified: bool = False
    
    # Raw metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionMatch(BaseModel):
    """A single detection match within content."""
    
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    matched_text: str
    start_position: int
    end_position: int
    pattern_name: Optional[str] = None
    explanation: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM


class DetectionResult(BaseModel):
    """Result of injection detection analysis."""
    
    # Overall assessment
    is_injection_detected: bool
    overall_risk: RiskLevel
    overall_confidence: float = Field(ge=0.0, le=1.0)
    
    # Individual matches
    matches: List[DetectionMatch] = Field(default_factory=list)
    
    # Context information
    content_type: ContentType
    trust_level: TrustLevel
    
    # Processing metadata
    detector_name: str = ""
    processing_time_ms: float = 0.0
    
    # Recommendations
    should_block: bool = False
    should_sanitize: bool = False
    recommendations: List[str] = Field(default_factory=list)


class FilterResult(BaseModel):
    """Result of trusted content filtering (Layer 1)."""
    
    # Original content
    original_content: str
    
    # Filter decision
    is_filtered: bool
    filter_reason: Optional[str] = None
    
    # Trust assessment
    source: ContentSource
    calculated_trust_level: TrustLevel
    
    # Output
    filtered_content: Optional[str] = None
    
    # Metadata
    processing_time_ms: float = 0.0


class SanitizationResult(BaseModel):
    """Result of content sanitization (Layer 2)."""
    
    # Original content
    original_content: str
    
    # Sanitization outcome
    was_modified: bool
    sanitized_content: str
    
    # What was removed/modified
    removals: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Statistics
    removal_count: int = 0
    characters_removed: int = 0
    
    # Processing metadata
    processing_time_ms: float = 0.0


class FencedContent(BaseModel):
    """Content with cryptographic fencing (Layer 4)."""
    
    # Original content
    original_content: str
    
    # Fenced representation
    fenced_content: str
    
    # Fence metadata
    fence_id: str
    trust_level: TrustLevel
    content_type: ContentType
    
    # Cryptographic verification
    signature: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Verification status
    is_verified: bool = False


class PipelineResult(BaseModel):
    """Combined result from the full pipeline."""
    
    # Input
    original_content: str
    content_source: ContentSource
    
    # Layer results
    filter_result: Optional[FilterResult] = None
    sanitization_result: Optional[SanitizationResult] = None
    detection_result: Optional[DetectionResult] = None
    fenced_content: Optional[FencedContent] = None
    
    # Final output
    final_content: str
    is_safe: bool
    overall_risk: RiskLevel
    
    # Recommendations
    should_proceed: bool
    warnings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # Processing metadata
    total_processing_time_ms: float = 0.0
    layers_applied: List[str] = Field(default_factory=list)
