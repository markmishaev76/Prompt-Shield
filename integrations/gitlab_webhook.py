"""
GitLab Webhook Integration for Prompt Shield.

This module provides a FastAPI server that receives GitLab webhooks
and scans content for prompt injection attacks.

Usage:
    # Start the server
    uvicorn integrations.gitlab_webhook:app --host 0.0.0.0 --port 8080
    
    # Configure GitLab webhook:
    # Settings -> Webhooks -> Add webhook
    # URL: https://your-server.com/webhook/gitlab
    # Trigger: Issues events, Comments, Merge request events
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel

# Add parent to path for imports
import sys
sys.path.insert(0, '/Users/markmishaev/ai-sec/src')

from prompt_shield import PromptShieldPipeline, Config
from prompt_shield.types import ContentSource, ContentType, TrustLevel, RiskLevel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Prompt Shield - GitLab Integration",
    description="Webhook server for scanning GitLab content for prompt injections",
    version="1.0.0",
)

# Initialize pipeline
pipeline = PromptShieldPipeline(Config.default())

# Configuration - set these via environment variables in production
GITLAB_WEBHOOK_SECRET = "your-webhook-secret"  # Set via env var


class WebhookResponse(BaseModel):
    """Response model for webhook processing."""
    event_type: str
    content_id: str
    is_safe: bool
    risk_level: str
    warnings: list[str]
    recommendations: list[str]
    processing_time_ms: float


def verify_gitlab_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitLab webhook signature."""
    if not signature:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def get_trust_level_from_gitlab(user_access_level: Optional[int]) -> TrustLevel:
    """
    Map GitLab access levels to Prompt Shield trust levels.
    
    GitLab access levels:
    - 50: Owner
    - 40: Maintainer
    - 30: Developer
    - 20: Reporter
    - 10: Guest
    - 5: Minimal access
    """
    if user_access_level is None:
        return TrustLevel.ANONYMOUS
    
    level_map = {
        50: TrustLevel.ADMIN,       # Owner
        40: TrustLevel.MAINTAINER,  # Maintainer
        30: TrustLevel.DEVELOPER,   # Developer
        20: TrustLevel.REPORTER,    # Reporter
        10: TrustLevel.GUEST,       # Guest
        5: TrustLevel.EXTERNAL,     # Minimal access
    }
    
    return level_map.get(user_access_level, TrustLevel.EXTERNAL)


@app.post("/webhook/gitlab", response_model=WebhookResponse)
async def handle_gitlab_webhook(
    request: Request,
    x_gitlab_event: str = Header(None),
    x_gitlab_token: str = Header(None),
):
    """
    Handle incoming GitLab webhooks.
    
    Supported events:
    - Issue Hook: New/updated issues
    - Note Hook: Comments on issues/MRs
    - Merge Request Hook: New/updated MRs
    """
    # Get raw body for signature verification
    body = await request.body()
    
    # Verify webhook secret (optional but recommended)
    if GITLAB_WEBHOOK_SECRET != "your-webhook-secret":
        if x_gitlab_token != GITLAB_WEBHOOK_SECRET:
            raise HTTPException(status_code=401, detail="Invalid webhook token")
    
    # Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    logger.info(f"Received GitLab event: {x_gitlab_event}")
    
    # Route to appropriate handler
    if x_gitlab_event == "Issue Hook":
        return await handle_issue_event(payload)
    elif x_gitlab_event == "Note Hook":
        return await handle_note_event(payload)
    elif x_gitlab_event == "Merge Request Hook":
        return await handle_merge_request_event(payload)
    else:
        logger.warning(f"Unhandled event type: {x_gitlab_event}")
        return WebhookResponse(
            event_type=x_gitlab_event or "unknown",
            content_id="n/a",
            is_safe=True,
            risk_level="none",
            warnings=[],
            recommendations=[],
            processing_time_ms=0,
        )


async def handle_issue_event(payload: dict) -> WebhookResponse:
    """Handle issue creation/update events."""
    issue = payload.get("object_attributes", {})
    user = payload.get("user", {})
    
    # Extract content
    title = issue.get("title", "")
    description = issue.get("description", "")
    content = f"{title}\n\n{description}"
    
    # Determine trust level
    # Note: In production, fetch actual user access level from GitLab API
    trust_level = TrustLevel.EXTERNAL  # Default for webhook events
    
    # Create content source
    source = ContentSource(
        source_type=ContentType.ISSUE_CONTENT,
        source_id=str(issue.get("iid", "")),
        author_username=user.get("username"),
        author_email=user.get("email"),
        author_trust_level=trust_level,
        metadata={
            "project_id": payload.get("project", {}).get("id"),
            "project_name": payload.get("project", {}).get("name"),
            "action": issue.get("action"),
        },
    )
    
    # Process through Prompt Shield
    result = pipeline.process(content, source)
    
    # Log if risky
    if not result.is_safe:
        logger.warning(
            f"⚠️ Risky issue detected: #{issue.get('iid')} "
            f"by {user.get('username')} - Risk: {result.overall_risk.value}"
        )
    
    return WebhookResponse(
        event_type="issue",
        content_id=str(issue.get("iid", "")),
        is_safe=result.is_safe,
        risk_level=result.overall_risk.value,
        warnings=result.warnings,
        recommendations=result.recommendations,
        processing_time_ms=result.total_processing_time_ms,
    )


async def handle_note_event(payload: dict) -> WebhookResponse:
    """Handle comment events (notes)."""
    note = payload.get("object_attributes", {})
    user = payload.get("user", {})
    
    content = note.get("note", "")
    
    # Determine content type based on noteable_type
    noteable_type = note.get("noteable_type", "")
    if noteable_type == "Issue":
        content_type = ContentType.ISSUE_COMMENT
    elif noteable_type == "MergeRequest":
        content_type = ContentType.MERGE_REQUEST
    else:
        content_type = ContentType.TOOL_OUTPUT
    
    source = ContentSource(
        source_type=content_type,
        source_id=str(note.get("id", "")),
        author_username=user.get("username"),
        author_email=user.get("email"),
        author_trust_level=TrustLevel.EXTERNAL,
        metadata={
            "noteable_type": noteable_type,
            "noteable_id": note.get("noteable_id"),
        },
    )
    
    result = pipeline.process(content, source)
    
    if not result.is_safe:
        logger.warning(
            f"⚠️ Risky comment detected: {note.get('id')} "
            f"by {user.get('username')} - Risk: {result.overall_risk.value}"
        )
    
    return WebhookResponse(
        event_type="note",
        content_id=str(note.get("id", "")),
        is_safe=result.is_safe,
        risk_level=result.overall_risk.value,
        warnings=result.warnings,
        recommendations=result.recommendations,
        processing_time_ms=result.total_processing_time_ms,
    )


async def handle_merge_request_event(payload: dict) -> WebhookResponse:
    """Handle merge request events."""
    mr = payload.get("object_attributes", {})
    user = payload.get("user", {})
    
    title = mr.get("title", "")
    description = mr.get("description", "")
    content = f"{title}\n\n{description}"
    
    source = ContentSource(
        source_type=ContentType.MERGE_REQUEST,
        source_id=str(mr.get("iid", "")),
        author_username=user.get("username"),
        author_email=user.get("email"),
        author_trust_level=TrustLevel.EXTERNAL,
        metadata={
            "source_branch": mr.get("source_branch"),
            "target_branch": mr.get("target_branch"),
            "action": mr.get("action"),
        },
    )
    
    result = pipeline.process(content, source)
    
    if not result.is_safe:
        logger.warning(
            f"⚠️ Risky MR detected: !{mr.get('iid')} "
            f"by {user.get('username')} - Risk: {result.overall_risk.value}"
        )
    
    return WebhookResponse(
        event_type="merge_request",
        content_id=str(mr.get("iid", "")),
        is_safe=result.is_safe,
        risk_level=result.overall_risk.value,
        warnings=result.warnings,
        recommendations=result.recommendations,
        processing_time_ms=result.total_processing_time_ms,
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/scan")
async def scan_content(
    content: str,
    content_type: str = "issue_content",
    trust_level: str = "external",
    author_username: Optional[str] = None,
):
    """
    Direct content scanning endpoint.
    
    Useful for testing or manual scanning.
    """
    source = ContentSource(
        source_type=ContentType(content_type),
        author_username=author_username,
        author_trust_level=TrustLevel(trust_level),
    )
    
    result = pipeline.process(content, source)
    
    return {
        "is_safe": result.is_safe,
        "risk_level": result.overall_risk.value,
        "should_proceed": result.should_proceed,
        "warnings": result.warnings,
        "recommendations": result.recommendations,
        "fenced_content": result.fenced_content.fenced_content if result.fenced_content else None,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
