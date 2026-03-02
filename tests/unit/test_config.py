"""
Unit tests for configuration module.

Tests the Config class, factory methods, and configuration validation.
Edge cases include boundary values, invalid settings, and security-critical
configuration combinations.
"""

import pytest
from pydantic import ValidationError

from prompt_shield.config import (
    Config,
    TrustedFilterConfig,
    DataFilterConfig,
    DetectorConfig,
    PromptFenceConfig,
    LoggingConfig,
)
from prompt_shield.types import TrustLevel, RiskLevel


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_default_config_creates_successfully(self):
        """Default config should create without errors."""
        config = Config.default()

        assert config is not None
        assert isinstance(config, Config)

    def test_default_has_all_layers_enabled(self):
        """Default config should have all layers enabled."""
        config = Config.default()

        assert config.trusted_filter.enabled
        assert config.data_filter.enabled
        assert config.detector.enabled
        assert config.prompt_fence.enabled

    def test_default_fail_open_is_false(self):
        """Default config should fail closed (fail_open=False)."""
        config = Config.default()

        assert config.fail_open is False

    def test_default_strict_mode_is_false(self):
        """Default config should not be in strict mode."""
        config = Config.default()

        assert config.strict_mode is False

    def test_default_allows_external_contributors(self):
        """Default config should allow external contributors (OSS-friendly)."""
        config = Config.default()

        assert config.trusted_filter.allow_external is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL


class TestStrictConfiguration:
    """Tests for strict security configuration."""

    def test_strict_config_creates_successfully(self):
        """Strict config should create without errors."""
        config = Config.strict()

        assert config is not None
        assert config.strict_mode is True

    def test_strict_config_disallows_external(self):
        """Strict config should not allow external contributors."""
        config = Config.strict()

        assert config.trusted_filter.allow_external is False
        assert config.trusted_filter.allow_anonymous is False

    def test_strict_config_requires_developer_trust(self):
        """Strict config should require developer-level trust."""
        config = Config.strict()

        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER

    def test_strict_config_has_lower_confidence_threshold(self):
        """Strict config should have lower detection threshold (more sensitive)."""
        config = Config.strict()

        # Lower threshold = more detections
        assert config.detector.confidence_threshold < Config.default().detector.confidence_threshold
        assert config.detector.confidence_threshold == 0.5

    def test_strict_config_blocks_at_medium_risk(self):
        """Strict config should block at MEDIUM risk level."""
        config = Config.strict()

        assert config.block_threshold == RiskLevel.MEDIUM

    def test_strict_config_aggressive_sanitization(self):
        """Strict config should use aggressive sanitization."""
        config = Config.strict()

        assert config.data_filter.aggressiveness == "aggressive"

    def test_strict_config_higher_tool_output_sensitivity(self):
        """Strict config should have higher sensitivity for tool outputs."""
        config = Config.strict()

        assert config.detector.tool_output_sensitivity == 1.5


class TestPermissiveConfiguration:
    """Tests for permissive configuration."""

    def test_permissive_config_creates_successfully(self):
        """Permissive config should create without errors."""
        config = Config.permissive()

        assert config is not None

    def test_permissive_config_allows_anonymous(self):
        """Permissive config should allow anonymous users."""
        config = Config.permissive()

        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True

    def test_permissive_config_fails_open(self):
        """Permissive config should fail open (allow on errors)."""
        config = Config.permissive()

        assert config.fail_open is True

    def test_permissive_config_has_higher_confidence_threshold(self):
        """Permissive config should have higher threshold (less sensitive)."""
        config = Config.permissive()

        # Higher threshold = fewer detections, fewer false positives
        assert config.detector.confidence_threshold > Config.default().detector.confidence_threshold
        assert config.detector.confidence_threshold == 0.85

    def test_permissive_config_blocks_only_critical(self):
        """Permissive config should only block CRITICAL risk."""
        config = Config.permissive()

        assert config.block_threshold == RiskLevel.CRITICAL

    def test_permissive_config_minimal_sanitization(self):
        """Permissive config should use minimal sanitization."""
        config = Config.permissive()

        assert config.data_filter.aggressiveness == "minimal"


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig edge cases."""

    def test_empty_allowlists_by_default(self):
        """Allowlists should be empty by default."""
        config = TrustedFilterConfig()

        assert config.allowed_users == []
        assert config.allowed_domains == []

    def test_empty_blocklists_by_default(self):
        """Blocklists should be empty by default."""
        config = TrustedFilterConfig()

        assert config.blocked_users == []
        assert config.blocked_domains == []

    def test_can_set_custom_allowlist(self):
        """Should be able to set custom user allowlist."""
        config = TrustedFilterConfig(
            allowed_users=["admin", "security-team"]
        )

        assert len(config.allowed_users) == 2
        assert "admin" in config.allowed_users

    def test_can_set_custom_blocklist(self):
        """Should be able to set custom user blocklist."""
        config = TrustedFilterConfig(
            blocked_users=["suspicious-user"]
        )

        assert len(config.blocked_users) == 1
        assert "suspicious-user" in config.blocked_users

    def test_filter_settings_enabled_by_default(self):
        """Content filtering should be enabled by default."""
        config = TrustedFilterConfig()

        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is True

    def test_can_disable_specific_filters(self):
        """Should be able to disable specific content filters."""
        config = TrustedFilterConfig(
            filter_issue_content=False,
            filter_comments=True,
        )

        assert config.filter_issue_content is False
        assert config.filter_comments is True


class TestDataFilterConfig:
    """Tests for DataFilterConfig edge cases."""

    def test_default_sanitization_mode_is_remove(self):
        """Default sanitization mode should be 'remove'."""
        config = DataFilterConfig()

        assert config.mode == "remove"

    def test_default_aggressiveness_is_balanced(self):
        """Default aggressiveness should be 'balanced'."""
        config = DataFilterConfig()

        assert config.aggressiveness == "balanced"

    def test_preserves_code_and_docs_by_default(self):
        """Should preserve code and documentation by default."""
        config = DataFilterConfig()

        assert config.preserve_code_context is True
        assert config.preserve_documentation is True

    def test_does_not_remove_urls_by_default(self):
        """Should not remove URLs by default (often legitimate)."""
        config = DataFilterConfig()

        assert config.remove_urls is False
        assert config.remove_email_addresses is False

    def test_removes_instructions_by_default(self):
        """Should remove instructions by default."""
        config = DataFilterConfig()

        assert config.remove_instructions is True

    def test_max_content_length_has_reasonable_default(self):
        """Max content length should have reasonable default."""
        config = DataFilterConfig()

        assert config.max_content_length > 0
        assert config.max_content_length == 100000

    def test_can_set_custom_removal_patterns(self):
        """Should be able to set custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"PATTERN1", r"PATTERN2"]
        )

        assert len(config.custom_removal_patterns) == 2

    def test_empty_custom_patterns_by_default(self):
        """Custom patterns should be empty by default."""
        config = DataFilterConfig()

        assert config.custom_removal_patterns == []


class TestDetectorConfig:
    """Tests for DetectorConfig edge cases."""

    def test_default_confidence_threshold_is_valid(self):
        """Default confidence threshold should be valid (0-1)."""
        config = DetectorConfig()

        assert 0.0 <= config.confidence_threshold <= 1.0
        assert config.confidence_threshold == 0.7

    def test_all_detector_components_enabled_by_default(self):
        """All detector components should be enabled by default."""
        config = DetectorConfig()

        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_context_aware_enabled_by_default(self):
        """Context awareness should be enabled by default (critical for indirect injection)."""
        config = DetectorConfig()

        assert config.context_aware is True

    def test_tool_output_sensitivity_greater_than_one(self):
        """Tool output sensitivity should be > 1 (higher sensitivity)."""
        config = DetectorConfig()

        assert config.tool_output_sensitivity > 1.0
        assert config.tool_output_sensitivity == 1.2

    def test_allows_code_and_docs_by_default(self):
        """Should allow code instructions and documentation examples by default."""
        config = DetectorConfig()

        assert config.allow_code_instructions is True
        assert config.allow_documentation_examples is True

    def test_custom_patterns_empty_by_default(self):
        """Custom patterns should be empty by default."""
        config = DetectorConfig()

        assert config.custom_patterns == {}

    def test_can_set_custom_patterns(self):
        """Should be able to set custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_attack": r"malicious\s*pattern"
            }
        )

        assert len(config.custom_patterns) == 1
        assert "custom_attack" in config.custom_patterns

    def test_ml_model_has_default(self):
        """ML model should have a default value."""
        config = DetectorConfig()

        assert config.ml_model_name is not None
        assert len(config.ml_model_name) > 0

    def test_ml_batch_size_is_positive(self):
        """ML batch size should be positive."""
        config = DetectorConfig()

        assert config.ml_batch_size > 0

    def test_ml_max_length_is_positive(self):
        """ML max length should be positive."""
        config = DetectorConfig()

        assert config.ml_max_length > 0


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig edge cases."""

    def test_default_fence_format_is_xml(self):
        """Default fence format should be XML."""
        config = PromptFenceConfig()

        assert config.fence_format == "xml"

    def test_uses_signatures_by_default(self):
        """Should use cryptographic signatures by default."""
        config = PromptFenceConfig()

        assert config.use_signatures is True

    def test_signature_algorithm_is_secure(self):
        """Signature algorithm should be secure (HMAC-SHA256)."""
        config = PromptFenceConfig()

        assert "hmac" in config.signature_algorithm.lower()
        assert "sha256" in config.signature_algorithm.lower()

    def test_includes_metadata_by_default(self):
        """Should include metadata by default."""
        config = PromptFenceConfig()

        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True

    def test_delimiters_are_distinct(self):
        """Trusted and untrusted delimiters should be different."""
        config = PromptFenceConfig()

        assert config.trusted_prefix != config.untrusted_prefix
        assert config.trusted_suffix != config.untrusted_suffix

    def test_delimiters_are_nonempty(self):
        """Delimiters should not be empty strings."""
        config = PromptFenceConfig()

        assert len(config.trusted_prefix) > 0
        assert len(config.trusted_suffix) > 0
        assert len(config.untrusted_prefix) > 0
        assert len(config.untrusted_suffix) > 0


class TestLoggingConfig:
    """Tests for LoggingConfig edge cases."""

    def test_logging_enabled_by_default(self):
        """Logging should be enabled by default."""
        config = LoggingConfig()

        assert config.enabled is True

    def test_default_log_level_is_info(self):
        """Default log level should be INFO."""
        config = LoggingConfig()

        assert config.log_level == "INFO"

    def test_logs_security_events_by_default(self):
        """Should log detections and sanitizations by default."""
        config = LoggingConfig()

        assert config.log_detections is True
        assert config.log_sanitizations is True

    def test_redacts_content_by_default(self):
        """Should redact sensitive content in logs by default."""
        config = LoggingConfig()

        assert config.redact_content is True

    def test_max_logged_content_has_limit(self):
        """Max logged content should have a reasonable limit."""
        config = LoggingConfig()

        assert config.max_logged_content_length > 0
        assert config.max_logged_content_length < 1000  # Not too large


class TestConfigValidation:
    """Tests for configuration validation and edge cases."""

    def test_can_create_config_with_all_layers_disabled(self):
        """Should be able to disable all layers (edge case)."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False),
        )

        assert config.trusted_filter.enabled is False
        assert config.data_filter.enabled is False
        assert config.detector.enabled is False
        assert config.prompt_fence.enabled is False

    def test_performance_settings_have_defaults(self):
        """Performance settings should have reasonable defaults."""
        config = Config.default()

        assert config.enable_caching is True
        assert config.cache_ttl_seconds > 0
        assert config.max_concurrent_requests > 0
        assert config.request_timeout_seconds > 0

    def test_can_set_custom_thresholds(self):
        """Should be able to set custom risk thresholds."""
        config = Config(
            block_threshold=RiskLevel.HIGH,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.LOW

    def test_zero_cache_ttl_is_valid(self):
        """Zero cache TTL should be valid (no caching)."""
        config = Config(cache_ttl_seconds=0)

        assert config.cache_ttl_seconds == 0

    def test_very_high_timeout_is_valid(self):
        """Should accept very high timeout values."""
        config = Config(request_timeout_seconds=600.0)

        assert config.request_timeout_seconds == 600.0


class TestConfigSerialization:
    """Tests for configuration serialization/deserialization."""

    def test_can_serialize_default_config(self):
        """Default config should serialize to dict."""
        config = Config.default()

        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_can_deserialize_config(self):
        """Should be able to deserialize config from dict."""
        config = Config.default()
        config_dict = config.model_dump()

        # Recreate from dict
        new_config = Config(**config_dict)

        assert new_config.strict_mode == config.strict_mode
        assert new_config.detector.confidence_threshold == config.detector.confidence_threshold

    def test_serialization_roundtrip_preserves_values(self):
        """Serialization roundtrip should preserve all values."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold
        assert restored.trusted_filter.minimum_trust_level == original.trusted_filter.minimum_trust_level


class TestSecurityCriticalSettings:
    """Tests for security-critical configuration combinations."""

    def test_fail_open_with_strict_mode_allowed(self):
        """Should allow fail_open=True with strict_mode (edge case for testing)."""
        # This is technically a weird combination but should be valid
        config = Config(
            fail_open=True,
            strict_mode=True,
        )

        assert config.fail_open is True
        assert config.strict_mode is True

    def test_disabled_detector_with_high_block_threshold(self):
        """Should allow disabled detector (edge case, though risky)."""
        config = Config(
            detector=DetectorConfig(enabled=False),
            block_threshold=RiskLevel.CRITICAL,
        )

        assert config.detector.enabled is False

    def test_anonymous_allowed_with_high_trust_requirement(self):
        """Should allow anonymous users with high minimum trust level."""
        # This combination doesn't make logical sense, but should be valid
        # (anonymous users would always fail the trust check)
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allow_anonymous=True,
                minimum_trust_level=TrustLevel.ADMIN,
            )
        )

        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.ADMIN

    def test_very_low_confidence_threshold(self):
        """Should allow very low confidence threshold (high sensitivity)."""
        config = Config(
            detector=DetectorConfig(confidence_threshold=0.1)
        )

        assert config.detector.confidence_threshold == 0.1

    def test_very_high_confidence_threshold(self):
        """Should allow very high confidence threshold (low sensitivity)."""
        config = Config(
            detector=DetectorConfig(confidence_threshold=0.99)
        )

        assert config.detector.confidence_threshold == 0.99

    def test_all_content_filtering_disabled(self):
        """Should allow disabling all content filtering (edge case)."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                filter_issue_content=False,
                filter_comments=False,
                filter_file_content=False,
                filter_wiki_pages=False,
            )
        )

        assert config.trusted_filter.filter_issue_content is False
        assert config.trusted_filter.filter_comments is False
        assert config.trusted_filter.filter_file_content is False
        assert config.trusted_filter.filter_wiki_pages is False
