"""
Unit tests for Layer 1: Trusted Content Filter.

Tests the trust-based filtering logic in isolation.
"""

import pytest

from prompt_shield.layers.trusted_filter import TrustedContentFilter
from prompt_shield.config import TrustedFilterConfig
from prompt_shield.types import ContentSource, ContentType, TrustLevel


class TestTrustHierarchy:
    """Tests for trust level hierarchy."""
    
    def test_system_is_highest_trust(self):
        """System trust should be highest."""
        filter = TrustedContentFilter()
        assert filter.TRUST_HIERARCHY[TrustLevel.SYSTEM] == 100
    
    def test_untrusted_is_lowest_trust(self):
        """Untrusted should be lowest (0)."""
        filter = TrustedContentFilter()
        assert filter.TRUST_HIERARCHY[TrustLevel.UNTRUSTED] == 0
    
    def test_trust_hierarchy_order(self):
        """Trust levels should be properly ordered."""
        filter = TrustedContentFilter()
        h = filter.TRUST_HIERARCHY
        
        assert h[TrustLevel.SYSTEM] > h[TrustLevel.ADMIN]
        assert h[TrustLevel.ADMIN] > h[TrustLevel.MAINTAINER]
        assert h[TrustLevel.MAINTAINER] > h[TrustLevel.DEVELOPER]
        assert h[TrustLevel.DEVELOPER] > h[TrustLevel.REPORTER]
        assert h[TrustLevel.REPORTER] > h[TrustLevel.GUEST]
        assert h[TrustLevel.GUEST] > h[TrustLevel.EXTERNAL]
        assert h[TrustLevel.EXTERNAL] > h[TrustLevel.ANONYMOUS]


class TestFilterDisabled:
    """Tests when filtering is disabled."""
    
    def test_disabled_filter_passes_all(self):
        """Disabled filter should pass everything through."""
        config = TrustedFilterConfig(enabled=False)
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.ANONYMOUS,
        )
        
        result = filter.filter("Malicious content", source)
        
        assert not result.is_filtered
        assert result.filtered_content == "Malicious content"


class TestTrustLevelFiltering:
    """Tests for trust level-based filtering."""
    
    def test_filter_below_minimum_trust(self):
        """Content from users below minimum trust should be filtered."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.DEVELOPER,
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.REPORTER,  # Below DEVELOPER
        )
        
        result = filter.filter("Some content", source)
        
        assert result.is_filtered
        assert "trust level" in result.filter_reason.lower()
    
    def test_pass_at_minimum_trust(self):
        """Content at minimum trust level should pass."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.DEVELOPER,
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.DEVELOPER,
        )
        
        result = filter.filter("Some content", source)
        
        assert not result.is_filtered
    
    def test_pass_above_minimum_trust(self):
        """Content above minimum trust level should pass."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.DEVELOPER,
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.MAINTAINER,  # Above DEVELOPER
        )
        
        result = filter.filter("Some content", source)
        
        assert not result.is_filtered


class TestAnonymousFiltering:
    """Tests for anonymous user filtering."""
    
    def test_block_anonymous_when_disabled(self):
        """Anonymous users should be blocked when allow_anonymous=False."""
        config = TrustedFilterConfig(
            allow_anonymous=False,
            minimum_trust_level=TrustLevel.ANONYMOUS,  # Even at lowest threshold
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.ANONYMOUS,
        )
        
        result = filter.filter("Some content", source)
        
        assert result.is_filtered
    
    def test_allow_anonymous_when_enabled(self):
        """Anonymous users should be allowed when allow_anonymous=True."""
        config = TrustedFilterConfig(
            allow_anonymous=True,
            minimum_trust_level=TrustLevel.ANONYMOUS,
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.ANONYMOUS,
        )
        
        result = filter.filter("Some content", source)
        
        assert not result.is_filtered


class TestAllowlistBlocklist:
    """Tests for allowlist/blocklist functionality."""
    
    def test_blocklist_user_by_username(self):
        """Blocklisted users should be filtered."""
        config = TrustedFilterConfig(
            blocked_users=["malicious_user"],
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_username="malicious_user",
            author_trust_level=TrustLevel.DEVELOPER,
        )
        
        result = filter.filter("Some content", source)
        
        assert result.is_filtered
        assert "blocklist" in result.filter_reason.lower()
    
    def test_allowlist_bypasses_trust_check(self):
        """Allowlisted users should bypass trust level checks."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.MAINTAINER,
            allowed_users=["special_user"],
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_username="special_user",
            author_trust_level=TrustLevel.GUEST,  # Below minimum
        )
        
        result = filter.filter("Some content", source)
        
        assert not result.is_filtered
    
    def test_blocklist_domain(self):
        """Blocklisted domains should be filtered."""
        config = TrustedFilterConfig(
            blocked_domains=["evil.com"],
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_email="attacker@evil.com",
            author_trust_level=TrustLevel.DEVELOPER,
        )
        
        result = filter.filter("Some content", source)
        
        assert result.is_filtered
        assert "blocklist" in result.filter_reason.lower()


class TestSystemContent:
    """Tests for system-generated content."""
    
    def test_system_messages_always_trusted(self):
        """System messages should always be trusted."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.ADMIN,
        )
        filter = TrustedContentFilter(config)
        
        source = ContentSource(
            source_type=ContentType.SYSTEM_MESSAGE,
            author_trust_level=TrustLevel.SYSTEM,  # System messages from system
        )
        
        result = filter.filter("System notification", source)
        
        assert not result.is_filtered
        # Trust level should be at least SYSTEM level
        assert result.calculated_trust_level in (TrustLevel.SYSTEM, TrustLevel.ADMIN)
    
    def test_api_responses_trusted(self):
        """API responses should be trusted."""
        filter = TrustedContentFilter()
        
        source = ContentSource(
            source_type=ContentType.API_RESPONSE,
            author_trust_level=TrustLevel.SYSTEM,
        )
        
        result = filter.filter("API data", source)
        
        # API responses should have high trust
        assert result.calculated_trust_level in (TrustLevel.SYSTEM, TrustLevel.ADMIN)


class TestTrustScoreCalculation:
    """Tests for trust score calculation."""
    
    def test_get_trust_score_admin(self):
        """Admin should have high trust score."""
        filter = TrustedContentFilter()
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.ADMIN,
        )
        
        score = filter.get_trust_score(source)
        
        assert score == 90
    
    def test_is_trusted_helper(self):
        """is_trusted helper should work correctly."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.DEVELOPER,
        )
        filter = TrustedContentFilter(config)
        
        trusted_source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.MAINTAINER,
        )
        untrusted_source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.GUEST,
        )
        
        assert filter.is_trusted(trusted_source) is True
        assert filter.is_trusted(untrusted_source) is False


class TestProcessingTime:
    """Tests for processing time tracking."""
    
    def test_processing_time_recorded(self):
        """Processing time should be recorded."""
        filter = TrustedContentFilter()
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.DEVELOPER,
        )
        
        result = filter.filter("Some content", source)
        
        assert result.processing_time_ms >= 0
