"""
Unit tests for configuration system.

Tests Config class validation, factory methods, and edge cases.
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


class TestConfigFactoryMethods:
    """Tests for Config factory methods."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = Config.default()

        assert config is not None
        assert config.trusted_filter.enabled
        assert config.data_filter.enabled
        assert config.detector.enabled
        assert config.prompt_fence.enabled

    def test_strict_config_more_restrictive(self):
        """Strict config should be more restrictive than default."""
        default = Config.default()
        strict = Config.strict()

        # Strict should require higher trust level (DEVELOPER vs EXTERNAL)
        # Check the actual trust level, not string comparison
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert default.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL

        # Strict should not allow anonymous/external
        assert not strict.trusted_filter.allow_anonymous
        assert not strict.trusted_filter.allow_external

        # Strict should block at MEDIUM risk (vs default HIGH)
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert default.block_threshold == RiskLevel.HIGH

        # Strict should have lower confidence threshold (more sensitive)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

    def test_permissive_config_less_restrictive(self):
        """Permissive config should be less restrictive than default."""
        default = Config.default()
        permissive = Config.permissive()

        # Permissive should allow more content
        assert permissive.trusted_filter.allow_anonymous
        assert permissive.trusted_filter.allow_external

        # Permissive should fail open
        assert permissive.fail_open

        # Permissive should have higher confidence threshold (less sensitive)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Permissive should only block critical risks
        assert permissive.block_threshold == RiskLevel.CRITICAL

    def test_strict_mode_flag(self):
        """Strict config should have strict_mode enabled."""
        strict = Config.strict()
        assert strict.strict_mode


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation."""

    def test_default_values(self):
        """TrustedFilterConfig should have sensible defaults."""
        config = TrustedFilterConfig()

        assert config.enabled
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external
        assert config.filter_issue_content
        assert config.filter_comments
        assert config.filter_file_content

    def test_custom_allowed_users(self):
        """Should accept custom allowed users list."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob", "charlie"]
        )

        assert len(config.allowed_users) == 3
        assert "alice" in config.allowed_users

    def test_custom_blocked_domains(self):
        """Should accept custom blocked domains list."""
        config = TrustedFilterConfig(
            blocked_domains=["evil.com", "suspicious.net"]
        )

        assert len(config.blocked_domains) == 2
        assert "evil.com" in config.blocked_domains

    def test_disable_all_filtering(self):
        """Should allow disabling all content filtering."""
        config = TrustedFilterConfig(
            filter_issue_content=False,
            filter_comments=False,
            filter_file_content=False,
            filter_wiki_pages=False,
        )

        assert not config.filter_issue_content
        assert not config.filter_comments
        assert not config.filter_file_content
        assert not config.filter_wiki_pages


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_default_mode(self):
        """Default sanitization mode should be 'remove'."""
        config = DataFilterConfig()
        assert config.mode == "remove"

    def test_aggressiveness_levels(self):
        """Should support different aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_boundary(self):
        """Should enforce max content length."""
        config = DataFilterConfig(max_content_length=1000)
        assert config.max_content_length == 1000

    def test_zero_max_content_length(self):
        """Should allow zero max content length (edge case)."""
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0

    def test_preserve_settings(self):
        """Should allow configuring preservation settings."""
        config = DataFilterConfig(
            preserve_code_context=False,
            preserve_documentation=False,
        )

        assert not config.preserve_code_context
        assert not config.preserve_documentation

    def test_custom_removal_patterns(self):
        """Should accept custom regex patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"\[SECRET\]", r"PASSWORD:\s*\S+"]
        )

        assert len(config.custom_removal_patterns) == 2


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_confidence_threshold_range(self):
        """Confidence threshold should be valid probability."""
        # Valid values
        for threshold in [0.0, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_min_risk_level_setting(self):
        """Should accept all risk levels."""
        for level in [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            config = DetectorConfig(min_risk_level=level)
            assert config.min_risk_level == level

    def test_disable_ml_model(self):
        """Should allow disabling ML model."""
        config = DetectorConfig(use_ml_model=False)
        assert not config.use_ml_model

    def test_disable_pattern_matching(self):
        """Should allow disabling pattern matching."""
        config = DetectorConfig(use_pattern_matching=False)
        assert not config.use_pattern_matching

    def test_disable_all_detectors(self):
        """Should allow disabling all detection methods (edge case)."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert not config.use_pattern_matching
        assert not config.use_ml_model
        assert not config.use_heuristics

    def test_custom_patterns(self):
        """Should accept custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_attack": r"malicious\s+pattern",
                "another_attack": r"dangerous\s+content",
            }
        )

        assert len(config.custom_patterns) == 2
        assert "custom_attack" in config.custom_patterns

    def test_ml_model_settings(self):
        """Should configure ML model parameters."""
        config = DetectorConfig(
            ml_model_name="custom/model",
            ml_batch_size=16,
            ml_max_length=256,
        )

        assert config.ml_model_name == "custom/model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_context_awareness(self):
        """Should allow configuring context awareness."""
        config = DetectorConfig(
            context_aware=True,
            tool_output_sensitivity=1.5,
        )

        assert config.context_aware
        assert config.tool_output_sensitivity == 1.5


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_fence_formats(self):
        """Should support different fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_cryptographic_settings(self):
        """Should configure signature settings."""
        config = PromptFenceConfig(
            use_signatures=True,
            signature_algorithm="hmac-sha256",
        )

        assert config.use_signatures
        assert config.signature_algorithm == "hmac-sha256"

    def test_disable_signatures(self):
        """Should allow disabling signatures."""
        config = PromptFenceConfig(use_signatures=False)
        assert not config.use_signatures

    def test_custom_delimiters(self):
        """Should accept custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<SAFE>>>",
            trusted_suffix="<<<END_SAFE>>>",
        )

        assert config.trusted_prefix == "<<<SAFE>>>"
        assert config.trusted_suffix == "<<<END_SAFE>>>"

    def test_metadata_settings(self):
        """Should configure metadata inclusion."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )

        assert config.include_metadata
        assert config.include_trust_level
        assert config.include_source_type


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_log_levels(self):
        """Should accept standard log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_disable_logging(self):
        """Should allow disabling logging."""
        config = LoggingConfig(enabled=False)
        assert not config.enabled

    def test_redact_content(self):
        """Should configure content redaction."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100,
        )

        assert config.redact_content
        assert config.max_logged_content_length == 100

    def test_selective_logging(self):
        """Should allow selective logging."""
        config = LoggingConfig(
            log_detections=True,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.log_detections
        assert not config.log_sanitizations
        assert not config.log_processing_times


class TestConfigValidation:
    """Tests for Config validation and edge cases."""

    def test_negative_cache_ttl(self):
        """Should handle negative cache TTL (edge case)."""
        config = Config(cache_ttl_seconds=-1)
        assert config.cache_ttl_seconds == -1

    def test_zero_timeout(self):
        """Should handle zero timeout."""
        config = Config(request_timeout_seconds=0.0)
        assert config.request_timeout_seconds == 0.0

    def test_very_large_timeout(self):
        """Should handle very large timeout values."""
        config = Config(request_timeout_seconds=999999.0)
        assert config.request_timeout_seconds == 999999.0

    def test_zero_max_concurrent_requests(self):
        """Should handle zero concurrent requests (edge case)."""
        config = Config(max_concurrent_requests=0)
        assert config.max_concurrent_requests == 0

    def test_fail_open_with_strict_mode(self):
        """Should allow fail_open with strict_mode (contradictory but valid)."""
        config = Config(fail_open=True, strict_mode=True)

        assert config.fail_open
        assert config.strict_mode

    def test_disable_all_layers(self):
        """Should allow disabling all layers (edge case for testing)."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False),
        )

        assert not config.trusted_filter.enabled
        assert not config.data_filter.enabled
        assert not config.detector.enabled
        assert not config.prompt_fence.enabled

    def test_config_serialization(self):
        """Config should be serializable to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict

    def test_config_deserialization(self):
        """Config should be deserializable from dict."""
        config_dict = {
            "fail_open": False,
            "strict_mode": True,
            "enable_caching": True,
        }

        config = Config(**config_dict)

        assert not config.fail_open
        assert config.strict_mode
        assert config.enable_caching

    def test_partial_config_override(self):
        """Should allow partial config override."""
        config = Config(
            detector=DetectorConfig(confidence_threshold=0.95),
        )

        # Overridden value
        assert config.detector.confidence_threshold == 0.95

        # Default values still present
        assert config.detector.enabled
        assert config.trusted_filter.enabled

    def test_nested_config_override(self):
        """Should allow deeply nested config override."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allowed_users=["admin", "operator"],
                blocked_domains=["malicious.com"],
            ),
            detector=DetectorConfig(
                custom_patterns={"test": r"pattern"},
            ),
        )

        assert len(config.trusted_filter.allowed_users) == 2
        assert "admin" in config.trusted_filter.allowed_users
        assert len(config.detector.custom_patterns) == 1


class TestConfigEdgeCases:
    """Tests for unusual but valid edge cases."""

    def test_empty_lists(self):
        """Should handle empty lists for allowlists/blocklists."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allowed_users=[],
                blocked_users=[],
                allowed_domains=[],
                blocked_domains=[],
            ),
        )

        assert len(config.trusted_filter.allowed_users) == 0
        assert len(config.trusted_filter.blocked_domains) == 0

    def test_very_long_custom_patterns(self):
        """Should handle very long regex patterns."""
        long_pattern = r"(?:" + "|".join([f"word{i}" for i in range(1000)]) + r")"

        config = DetectorConfig(
            custom_patterns={"long_pattern": long_pattern}
        )

        assert "long_pattern" in config.custom_patterns
        assert len(config.custom_patterns["long_pattern"]) > 1000

    def test_unicode_in_patterns(self):
        """Should handle Unicode characters in patterns."""
        config = DetectorConfig(
            custom_patterns={
                "unicode_pattern": r"攻击|公鸡|🚨",
            }
        )

        assert "unicode_pattern" in config.custom_patterns

    def test_empty_custom_patterns(self):
        """Should handle empty custom patterns dict."""
        config = DetectorConfig(custom_patterns={})
        assert len(config.custom_patterns) == 0

    def test_extreme_confidence_boundaries(self):
        """Should handle extreme confidence values at boundaries."""
        # Exactly 0.0
        config1 = DetectorConfig(confidence_threshold=0.0)
        assert config1.confidence_threshold == 0.0

        # Exactly 1.0
        config2 = DetectorConfig(confidence_threshold=1.0)
        assert config2.confidence_threshold == 1.0

    def test_very_short_fence_delimiters(self):
        """Should handle very short fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<",
            trusted_suffix=">",
        )

        assert config.trusted_prefix == "<"
        assert config.trusted_suffix == ">"

    def test_identical_fence_delimiters(self):
        """Should allow identical prefix and suffix (edge case)."""
        config = PromptFenceConfig(
            trusted_prefix="|||",
            trusted_suffix="|||",
        )

        assert config.trusted_prefix == config.trusted_suffix
