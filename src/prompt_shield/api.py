"""
REST API for Prompt Shield.

Provides HTTP endpoints for integration with other services.
"""

from __future__ import annotations

from typing import List, Optional
import logging

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
    HAS_API_DEPS = True
except ImportError:
    HAS_API_DEPS = False

from prompt_shield.pipeline import PromptShieldPipeline
from prompt_shield.config import Config
from prompt_shield.types import ContentType, TrustLevel, ContentSource, RiskLevel

logger = logging.getLogger(__name__)


# Request/Response models
class DetectRequest(BaseModel):
    """Request to detect prompt injection."""
    
    content: str = Field(..., description="Content to analyze")
    content_type: str = Field(
        default="tool_output",
        description="Type of content (tool_output, issue_content, file_content, etc.)",
    )
    trust_level: str = Field(
        default="untrusted",
        description="Trust level of content source",
    )
    author_username: Optional[str] = Field(
        default=None,
        description="Username of content author",
    )
    source_id: Optional[str] = Field(
        default=None,
        description="ID of content source (e.g., issue ID)",
    )


class DetectionMatch(BaseModel):
    """A single detection match."""
    
    attack_type: str
    confidence: float
    matched_text: str
    pattern_name: Optional[str]
    severity: str
    explanation: str


class DetectResponse(BaseModel):
    """Response from detection endpoint."""
    
    is_safe: bool
    overall_risk: str
    should_proceed: bool
    warnings: List[str]
    recommendations: List[str]
    matches: List[DetectionMatch] = []
    sanitized_content: Optional[str] = None
    fenced_content: Optional[str] = None
    processing_time_ms: float
    layers_applied: List[str]


class FenceRequest(BaseModel):
    """Request to apply prompt fencing."""
    
    content: str
    trust_level: str = "untrusted"
    format: str = "xml"  # xml, markdown, json, delimiter


class FenceResponse(BaseModel):
    """Response from fence endpoint."""
    
    fenced_content: str
    fence_id: str
    trust_level: str
    signature: str


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str
    version: str


if HAS_API_DEPS:
    # Initialize FastAPI app
    app = FastAPI(
        title="Prompt Shield API",
        description="Multi-layered defense against indirect prompt injection attacks",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    # Initialize pipeline (singleton)
    _pipeline: Optional[PromptShieldPipeline] = None
    
    def get_pipeline() -> PromptShieldPipeline:
        global _pipeline
        if _pipeline is None:
            _pipeline = PromptShieldPipeline(Config.default())
        return _pipeline
    
    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check endpoint."""
        from prompt_shield import __version__
        return HealthResponse(status="healthy", version=__version__)
    
    @app.post("/detect", response_model=DetectResponse)
    async def detect(request: DetectRequest):
        """
        Detect prompt injection in content.
        
        This is the main detection endpoint. It processes content through
        all defense layers and returns a comprehensive analysis.
        """
        pipeline = get_pipeline()
        
        # Parse enums
        try:
            ct = ContentType(request.content_type)
        except ValueError:
            ct = ContentType.TOOL_OUTPUT
        
        try:
            tl = TrustLevel(request.trust_level)
        except ValueError:
            tl = TrustLevel.UNTRUSTED
        
        # Build source
        source = ContentSource(
            source_type=ct,
            source_id=request.source_id,
            author_username=request.author_username,
            author_trust_level=tl,
        )
        
        # Process
        result = pipeline.process(request.content, source)
        
        # Build response
        matches = []
        if result.detection_result:
            matches = [
                DetectionMatch(
                    attack_type=m.attack_type.value,
                    confidence=m.confidence,
                    matched_text=m.matched_text[:200],  # Truncate
                    pattern_name=m.pattern_name,
                    severity=m.severity.value,
                    explanation=m.explanation,
                )
                for m in result.detection_result.matches
            ]
        
        return DetectResponse(
            is_safe=result.is_safe,
            overall_risk=result.overall_risk.value,
            should_proceed=result.should_proceed,
            warnings=result.warnings,
            recommendations=result.recommendations,
            matches=matches,
            sanitized_content=result.sanitization_result.sanitized_content if result.sanitization_result else None,
            fenced_content=result.fenced_content.fenced_content if result.fenced_content else None,
            processing_time_ms=result.total_processing_time_ms,
            layers_applied=result.layers_applied,
        )
    
    @app.post("/detect/quick")
    async def detect_quick(request: DetectRequest):
        """
        Quick detection - returns only essential information.
        
        Faster than full detection, suitable for real-time filtering.
        """
        pipeline = get_pipeline()
        
        try:
            ct = ContentType(request.content_type)
        except ValueError:
            ct = ContentType.TOOL_OUTPUT
        
        try:
            tl = TrustLevel(request.trust_level)
        except ValueError:
            tl = TrustLevel.UNTRUSTED
        
        source = ContentSource(source_type=ct, author_trust_level=tl)
        result = pipeline.process(request.content, source)
        
        return {
            "is_safe": result.is_safe,
            "risk": result.overall_risk.value,
            "proceed": result.should_proceed,
        }
    
    @app.post("/fence", response_model=FenceResponse)
    async def fence(request: FenceRequest):
        """
        Apply prompt fencing to content.
        
        Wraps content with trust metadata tags.
        """
        from prompt_shield.layers.prompt_fence import PromptFence
        from prompt_shield.config import PromptFenceConfig
        
        try:
            tl = TrustLevel(request.trust_level)
        except ValueError:
            tl = TrustLevel.UNTRUSTED
        
        config = PromptFenceConfig(fence_format=request.format)
        fence = PromptFence(config)
        
        result = fence.fence(request.content, trust_level=tl)
        
        return FenceResponse(
            fenced_content=result.fenced_content,
            fence_id=result.fence_id,
            trust_level=result.trust_level.value,
            signature=result.signature,
        )
    
    @app.post("/sanitize")
    async def sanitize(request: DetectRequest):
        """
        Sanitize content by removing malicious instructions.
        
        Returns sanitized content safe for LLM processing.
        """
        pipeline = get_pipeline()
        
        try:
            ct = ContentType(request.content_type)
        except ValueError:
            ct = ContentType.TOOL_OUTPUT
        
        source = ContentSource(source_type=ct)
        
        sanitization_result = pipeline.data_filter.sanitize(request.content, source)
        
        return {
            "original_content": request.content,
            "sanitized_content": sanitization_result.sanitized_content,
            "was_modified": sanitization_result.was_modified,
            "removal_count": sanitization_result.removal_count,
            "removals": sanitization_result.removals,
        }
    
    @app.get("/config")
    async def get_config():
        """Get current configuration."""
        pipeline = get_pipeline()
        return pipeline.config.model_dump()


def create_app(config: Optional[Config] = None) -> "FastAPI":
    """Create FastAPI app with custom config."""
    if not HAS_API_DEPS:
        raise ImportError("FastAPI dependencies not installed. Install with: pip install prompt-shield[api]")
    
    global _pipeline
    _pipeline = PromptShieldPipeline(config or Config.default())
    return app


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the API server."""
    if not HAS_API_DEPS:
        raise ImportError("API dependencies not installed. Install with: pip install prompt-shield[api]")
    
    import uvicorn
    uvicorn.run(app, host=host, port=port)
