"""
GitHub Action Integration for Prompt Shield.

This script is designed to run as part of a GitHub Action workflow.
It scans PR descriptions, issue content, and comments for prompt injections.

Usage in GitHub Action:
    - name: Scan for Prompt Injection
      run: python integrations/github_action.py
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        GITHUB_EVENT_PATH: ${{ github.event_path }}
        GITHUB_EVENT_NAME: ${{ github.event_name }}
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from prompt_shield import PromptShieldPipeline, Config
from prompt_shield.types import ContentSource, ContentType, TrustLevel, RiskLevel


def get_trust_level_from_github(association: Optional[str]) -> TrustLevel:
    """
    Map GitHub author association to Prompt Shield trust levels.
    
    GitHub associations:
    - OWNER: Repository owner
    - MEMBER: Organization member
    - COLLABORATOR: Direct collaborator
    - CONTRIBUTOR: Has contributed before
    - FIRST_TIME_CONTRIBUTOR: First contribution
    - FIRST_TIMER: First time on GitHub
    - NONE: No association
    """
    if association is None:
        return TrustLevel.ANONYMOUS
    
    association_map = {
        "OWNER": TrustLevel.ADMIN,
        "MEMBER": TrustLevel.MAINTAINER,
        "COLLABORATOR": TrustLevel.DEVELOPER,
        "CONTRIBUTOR": TrustLevel.REPORTER,
        "FIRST_TIME_CONTRIBUTOR": TrustLevel.EXTERNAL,
        "FIRST_TIMER": TrustLevel.EXTERNAL,
        "NONE": TrustLevel.ANONYMOUS,
    }
    
    return association_map.get(association.upper(), TrustLevel.EXTERNAL)


def scan_pull_request(event: dict, pipeline: PromptShieldPipeline) -> dict:
    """Scan a pull request for prompt injection."""
    pr = event.get("pull_request", {})
    
    title = pr.get("title", "")
    body = pr.get("body", "") or ""
    content = f"{title}\n\n{body}"
    
    user = pr.get("user", {})
    association = pr.get("author_association")
    
    source = ContentSource(
        source_type=ContentType.MERGE_REQUEST,
        source_id=str(pr.get("number", "")),
        author_username=user.get("login"),
        author_trust_level=get_trust_level_from_github(association),
        metadata={
            "repo": event.get("repository", {}).get("full_name"),
            "action": event.get("action"),
            "base_branch": pr.get("base", {}).get("ref"),
            "head_branch": pr.get("head", {}).get("ref"),
        },
    )
    
    result = pipeline.process(content, source)
    
    return {
        "type": "pull_request",
        "number": pr.get("number"),
        "is_safe": result.is_safe,
        "risk_level": result.overall_risk.value,
        "warnings": result.warnings,
        "recommendations": result.recommendations,
    }


def scan_issue(event: dict, pipeline: PromptShieldPipeline) -> dict:
    """Scan an issue for prompt injection."""
    issue = event.get("issue", {})
    
    title = issue.get("title", "")
    body = issue.get("body", "") or ""
    content = f"{title}\n\n{body}"
    
    user = issue.get("user", {})
    association = issue.get("author_association")
    
    source = ContentSource(
        source_type=ContentType.ISSUE_CONTENT,
        source_id=str(issue.get("number", "")),
        author_username=user.get("login"),
        author_trust_level=get_trust_level_from_github(association),
        metadata={
            "repo": event.get("repository", {}).get("full_name"),
            "action": event.get("action"),
        },
    )
    
    result = pipeline.process(content, source)
    
    return {
        "type": "issue",
        "number": issue.get("number"),
        "is_safe": result.is_safe,
        "risk_level": result.overall_risk.value,
        "warnings": result.warnings,
        "recommendations": result.recommendations,
    }


def scan_comment(event: dict, pipeline: PromptShieldPipeline) -> dict:
    """Scan a comment for prompt injection."""
    comment = event.get("comment", {})
    
    content = comment.get("body", "") or ""
    
    user = comment.get("user", {})
    association = comment.get("author_association")
    
    # Determine if it's an issue comment or PR comment
    if "issue" in event:
        content_type = ContentType.ISSUE_COMMENT
        parent_id = event["issue"].get("number")
    elif "pull_request" in event:
        content_type = ContentType.MERGE_REQUEST
        parent_id = event["pull_request"].get("number")
    else:
        content_type = ContentType.TOOL_OUTPUT
        parent_id = None
    
    source = ContentSource(
        source_type=content_type,
        source_id=str(comment.get("id", "")),
        author_username=user.get("login"),
        author_trust_level=get_trust_level_from_github(association),
        metadata={
            "repo": event.get("repository", {}).get("full_name"),
            "action": event.get("action"),
            "parent_id": parent_id,
        },
    )
    
    result = pipeline.process(content, source)
    
    return {
        "type": "comment",
        "id": comment.get("id"),
        "is_safe": result.is_safe,
        "risk_level": result.overall_risk.value,
        "warnings": result.warnings,
        "recommendations": result.recommendations,
    }


def main():
    """Main entry point for GitHub Action."""
    # Get event information
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    
    if not event_path or not os.path.exists(event_path):
        print("❌ No GitHub event file found")
        print("   This script should be run as part of a GitHub Action")
        sys.exit(1)
    
    # Load event data
    with open(event_path) as f:
        event = json.load(f)
    
    print(f"🔍 Prompt Shield - GitHub Action")
    print(f"   Event: {event_name}")
    print(f"   Repository: {event.get('repository', {}).get('full_name', 'unknown')}")
    print()
    
    # Initialize pipeline
    pipeline = PromptShieldPipeline(Config.default())
    
    # Route to appropriate handler
    if event_name == "pull_request":
        result = scan_pull_request(event, pipeline)
    elif event_name == "issues":
        result = scan_issue(event, pipeline)
    elif event_name in ("issue_comment", "pull_request_review_comment"):
        result = scan_comment(event, pipeline)
    else:
        print(f"⚠️ Unhandled event type: {event_name}")
        sys.exit(0)
    
    # Output results
    print(f"📋 Scan Results for {result['type']} #{result.get('number', result.get('id'))}")
    print(f"   Safe: {'✅' if result['is_safe'] else '❌'}")
    print(f"   Risk Level: {result['risk_level'].upper()}")
    
    if result['warnings']:
        print(f"   ⚠️ Warnings:")
        for warning in result['warnings']:
            print(f"      - {warning}")
    
    if result['recommendations']:
        print(f"   💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"      - {rec}")
    
    # Set output for GitHub Actions
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"is_safe={str(result['is_safe']).lower()}\n")
            f.write(f"risk_level={result['risk_level']}\n")
    
    # Exit with error if high/critical risk OR if threats were sanitized
    threats_sanitized = "Sanitized:" in str(result.get('warnings', []))
    
    if result['risk_level'] in ('high', 'critical'):
        print()
        print("🚫 Content blocked due to high risk level")
        sys.exit(1)
    elif threats_sanitized:
        print()
        print("⚠️ Potential threats were detected and sanitized")
        print("   Review the content before processing")
        sys.exit(1)
    
    print()
    print("✅ Scan complete")


if __name__ == "__main__":
    main()
