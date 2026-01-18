"""
Layer 1: Trusted Content Filter

Filters content based on author permissions and trust levels.
This is the first line of defense - reducing the attack surface by filtering
untrusted sources before processing.

Key features:
- Filter by author trust level (admin, maintainer, developer, etc.)
- Allowlists and blocklists for users and domains
- Content type-specific filtering rules
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from prompt_shield.types import (
    ContentSource,
    ContentType,
    FilterResult,
    TrustLevel,
)
from prompt_shield.config import TrustedFilterConfig

logger = logging.getLogger(__name__)


class TrustedContentFilter:
    """
    Layer 1: Filter content based on trust level and source.
    
    This layer determines whether content should be processed at all,
    based on who created it and from what source it came.
    """
    
    # Trust level hierarchy (higher = more trusted)
    TRUST_HIERARCHY: Dict[TrustLevel, int] = {
        TrustLevel.SYSTEM: 100,
        TrustLevel.ADMIN: 90,
        TrustLevel.MAINTAINER: 80,
        TrustLevel.DEVELOPER: 70,
        TrustLevel.REPORTER: 50,
        TrustLevel.GUEST: 30,
        TrustLevel.EXTERNAL: 20,
        TrustLevel.ANONYMOUS: 10,
        TrustLevel.UNTRUSTED: 0,
    }
    
    def __init__(self, config: Optional[TrustedFilterConfig] = None):
        self.config = config or TrustedFilterConfig()
        
        # Pre-compute allowlist/blocklist sets for efficiency
        self._allowed_users = set(self.config.allowed_users)
        self._blocked_users = set(self.config.blocked_users)
        self._allowed_domains = set(self.config.allowed_domains)
        self._blocked_domains = set(self.config.blocked_domains)
    
    def filter(self, content: str, source: ContentSource) -> FilterResult:
        """
        Filter content based on source trustworthiness.
        
        Args:
            content: The content to filter
            source: Metadata about the content source
            
        Returns:
            FilterResult with filtering decision and reasoning
        """
        import time
        start_time = time.time()
        
        # If filtering is disabled, pass through
        if not self.config.enabled:
            return FilterResult(
                original_content=content,
                is_filtered=False,
                filter_reason=None,
                source=source,
                calculated_trust_level=source.author_trust_level,
                filtered_content=content,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Check blocklists first
        block_reason = self._check_blocklists(source)
        if block_reason:
            logger.info(f"Content blocked by blocklist: {block_reason}")
            return FilterResult(
                original_content=content,
                is_filtered=True,
                filter_reason=block_reason,
                source=source,
                calculated_trust_level=TrustLevel.UNTRUSTED,
                filtered_content=None,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Check allowlists
        if self._check_allowlists(source):
            return FilterResult(
                original_content=content,
                is_filtered=False,
                filter_reason="Explicitly allowed by allowlist",
                source=source,
                calculated_trust_level=source.author_trust_level,
                filtered_content=content,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Calculate effective trust level
        trust_level = self._calculate_trust_level(source)
        
        # Check if trust level meets minimum threshold
        min_trust_score = self.TRUST_HIERARCHY.get(
            self.config.minimum_trust_level, 0
        )
        current_trust_score = self.TRUST_HIERARCHY.get(trust_level, 0)
        
        if current_trust_score < min_trust_score:
            reason = (
                f"Trust level {trust_level.value} ({current_trust_score}) "
                f"below minimum {self.config.minimum_trust_level.value} ({min_trust_score})"
            )
            logger.info(f"Content filtered: {reason}")
            return FilterResult(
                original_content=content,
                is_filtered=True,
                filter_reason=reason,
                source=source,
                calculated_trust_level=trust_level,
                filtered_content=None,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Check content type-specific rules
        filter_by_type = self._check_content_type_rules(source.source_type)
        if filter_by_type:
            logger.info(f"Content filtered by type rule: {filter_by_type}")
            return FilterResult(
                original_content=content,
                is_filtered=True,
                filter_reason=filter_by_type,
                source=source,
                calculated_trust_level=trust_level,
                filtered_content=None,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Content passes all filters
        return FilterResult(
            original_content=content,
            is_filtered=False,
            filter_reason=None,
            source=source,
            calculated_trust_level=trust_level,
            filtered_content=content,
            processing_time_ms=(time.time() - start_time) * 1000,
        )
    
    def _check_blocklists(self, source: ContentSource) -> Optional[str]:
        """Check if source is on any blocklist."""
        # Check user blocklist
        if source.author_username and source.author_username in self._blocked_users:
            return f"User {source.author_username} is blocklisted"
        
        if source.author_id and source.author_id in self._blocked_users:
            return f"User ID {source.author_id} is blocklisted"
        
        # Check domain blocklist
        if source.author_email:
            domain = source.author_email.split("@")[-1] if "@" in source.author_email else None
            if domain and domain in self._blocked_domains:
                return f"Domain {domain} is blocklisted"
        
        return None
    
    def _check_allowlists(self, source: ContentSource) -> bool:
        """Check if source is on any allowlist."""
        # Check user allowlist
        if source.author_username and source.author_username in self._allowed_users:
            return True
        
        if source.author_id and source.author_id in self._allowed_users:
            return True
        
        # Check domain allowlist
        if source.author_email:
            domain = source.author_email.split("@")[-1] if "@" in source.author_email else None
            if domain and domain in self._allowed_domains:
                return True
        
        return False
    
    def _calculate_trust_level(self, source: ContentSource) -> TrustLevel:
        """Calculate the effective trust level for a source."""
        # Start with the provided trust level
        trust_level = source.author_trust_level
        
        # Handle anonymous users
        if trust_level == TrustLevel.ANONYMOUS:
            if not self.config.allow_anonymous:
                return TrustLevel.UNTRUSTED
        
        # Handle external users
        if trust_level == TrustLevel.EXTERNAL:
            if not self.config.allow_external:
                return TrustLevel.UNTRUSTED
        
        # System content is always trusted
        if source.source_type == ContentType.SYSTEM_MESSAGE:
            return TrustLevel.SYSTEM
        
        # API responses are generally trusted
        if source.source_type == ContentType.API_RESPONSE:
            return TrustLevel.SYSTEM
        
        # Verified users get a trust boost
        if source.is_verified:
            trust_score = self.TRUST_HIERARCHY.get(trust_level, 0)
            # Find next higher trust level
            for level, score in sorted(self.TRUST_HIERARCHY.items(), key=lambda x: x[1]):
                if score > trust_score:
                    return level
        
        return trust_level
    
    def _check_content_type_rules(self, content_type: ContentType) -> Optional[str]:
        """Check content type-specific filtering rules."""
        if content_type == ContentType.ISSUE_CONTENT and not self.config.filter_issue_content:
            return None
        
        if content_type == ContentType.ISSUE_COMMENT and not self.config.filter_comments:
            return None
        
        if content_type == ContentType.FILE_CONTENT and not self.config.filter_file_content:
            return None
        
        if content_type == ContentType.WIKI_PAGE and not self.config.filter_wiki_pages:
            return None
        
        return None
    
    def is_trusted(self, source: ContentSource) -> bool:
        """Quick check if a source meets minimum trust requirements."""
        trust_level = self._calculate_trust_level(source)
        min_trust_score = self.TRUST_HIERARCHY.get(self.config.minimum_trust_level, 0)
        current_trust_score = self.TRUST_HIERARCHY.get(trust_level, 0)
        return current_trust_score >= min_trust_score
    
    def get_trust_score(self, source: ContentSource) -> int:
        """Get numeric trust score for a source."""
        trust_level = self._calculate_trust_level(source)
        return self.TRUST_HIERARCHY.get(trust_level, 0)
