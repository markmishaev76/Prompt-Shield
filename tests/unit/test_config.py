"""
Unit tests for configuration validation and edge cases.

Tests configuration parsing, validation, boundary conditions,
and preset configurations (default, strict, permissive).
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


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation and edge cases."""

    def test_default_config_values(self):
        """Default config should have expected values."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_anonymous is False
        assert config.allow_external is True
        assert config.filter_issue_content is True
        assert config.allowed_users == []
        assert config.blocked_users == []

    def test_empty_allowlists_and_blocklists(self):
        """Empty allowlists and blocklists should be valid."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
            allowed_domains=[],
            blocked_domains=[],
        )

        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []

    def test_allowlist_with_multiple_users(self):
        """Should accept multiple users in allowlist."""
        users = ["user1", "user2", "user3"]
        config = TrustedFilterConfig(allowed_users=users)

        assert config.allowed_users == users

    def test_blocklist_with_multiple_domains(self):
        """Should accept multiple domains in blocklist."""
        domains = ["evil.com", "attacker.net", "spam.org"]
        config = TrustedFilterConfig(blocked_domains=domains)

        assert config.blocked_domains == domains

    def test_conflicting_allow_settings(self):
        """Should allow conflicting allow settings (policy decides precedence)."""
        # Both anonymous and external disabled but minimum trust is external
        config = TrustedFilterConfig(
            allow_anonymous=False,
            allow_external=False,
            minimum_trust_level=TrustLevel.EXTERNAL,
        )

        # Configuration is valid, enforcement logic handles conflicts
        assert config.allow_anonymous is False
        assert config.allow_external is False


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation and edge cases."""

    def test_default_config_values(self):
        """Default config should have expected values."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.max_content_length == 100000
        assert config.preserve_code_context is True

    def test_valid_modes(self):
        """Should accept valid sanitization modes."""
        valid_modes = ["remove", "mask", "escape", "tag"]

        for mode in valid_modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness_levels(self):
        """Should accept valid aggressiveness levels."""
        valid_levels = ["minimal", "balanced", "aggressive"]

        for level in valid_levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_boundary_values(self):
        """Should handle boundary values for max content length."""
        # Very small length
        config = DataFilterConfig(max_content_length=1)
        assert config.max_content_length == 1

        # Very large length
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

        # Zero length (may be invalid in practice but config allows it)
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0

    def test_custom_removal_patterns_empty(self):
        """Empty custom patterns should be valid."""
        config = DataFilterConfig(custom_removal_patterns=[])
        assert config.custom_removal_patterns == []

    def test_custom_removal_patterns_with_regex(self):
        """Should accept custom regex patterns."""
        patterns = [r"\[HIDDEN\].*", r"(?i)secret[:\s]*\w+"]
        config = DataFilterConfig(custom_removal_patterns=patterns)

        assert config.custom_removal_patterns == patterns

    def test_all_removal_flags_disabled(self):
        """Should allow all removal flags to be disabled."""
        config = DataFilterConfig(
            remove_instructions=False,
            remove_code_blocks=False,
            remove_urls=False,
            remove_email_addresses=False,
        )

        assert config.remove_instructions is False
        assert config.remove_code_blocks is False


class TestDetectorConfig:
    """Tests for DetectorConfig validation and edge cases."""

    def test_default_config_values(self):
        """Default config should have expected values."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.confidence_threshold == 0.7
        assert config.min_risk_level == RiskLevel.LOW
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.context_aware is True

    def test_confidence_threshold_boundaries(self):
        """Should handle confidence threshold boundary values."""
        # Minimum confidence (0.0)
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

        # Maximum confidence (1.0)
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

        # Mid-range value
        config = DetectorConfig(confidence_threshold=0.5)
        assert config.confidence_threshold == 0.5

    def test_confidence_threshold_invalid_values(self):
        """Should validate confidence threshold range."""
        # Note: Pydantic may allow out-of-range floats unless explicitly constrained
        # This test documents current behavior
        config = DetectorConfig(confidence_threshold=1.5)
        assert config.confidence_threshold == 1.5  # No validation yet

        config = DetectorConfig(confidence_threshold=-0.1)
        assert config.confidence_threshold == -0.1  # No validation yet

    def test_all_detector_components_disabled(self):
        """Should allow disabling all detector components."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_ml_model_settings(self):
        """Should accept ML model configuration."""
        config = DetectorConfig(
            ml_model_name="custom/model",
            ml_batch_size=16,
            ml_max_length=256,
        )

        assert config.ml_model_name == "custom/model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_ml_batch_size_edge_cases(self):
        """Should handle ML batch size edge cases."""
        # Very small batch
        config = DetectorConfig(ml_batch_size=1)
        assert config.ml_batch_size == 1

        # Large batch
        config = DetectorConfig(ml_batch_size=128)
        assert config.ml_batch_size == 128

    def test_custom_patterns_empty(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_custom_patterns_with_entries(self):
        """Should accept custom pattern dictionary."""
        patterns = {
            "my_pattern": r"custom\s+regex",
            "another": r"(?i)test",
        }
        config = DetectorConfig(custom_patterns=patterns)

        assert config.custom_patterns == patterns

    def test_tool_output_sensitivity_boundary_values(self):
        """Should handle tool output sensitivity edge cases."""
        # No sensitivity boost
        config = DetectorConfig(tool_output_sensitivity=1.0)
        assert config.tool_output_sensitivity == 1.0

        # High sensitivity
        config = DetectorConfig(tool_output_sensitivity=2.5)
        assert config.tool_output_sensitivity == 2.5

        # Very low sensitivity
        config = DetectorConfig(tool_output_sensitivity=0.1)
        assert config.tool_output_sensitivity == 0.1


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation and edge cases."""

    def test_default_config_values(self):
        """Default config should have expected values."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"
        assert config.include_metadata is True

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        valid_formats = ["xml", "markdown", "json", "delimiter"]

        for fmt in valid_formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_custom_fence_delimiters(self):
        """Should accept custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<START>>>",
            trusted_suffix="<<<END>>>",
            untrusted_prefix="<<<UNTRUSTED>>>",
            untrusted_suffix="<<<DONE>>>",
        )

        assert config.trusted_prefix == "<<<START>>>"
        assert config.trusted_suffix == "<<<END>>>"

    def test_empty_delimiters(self):
        """Should allow empty delimiters (edge case)."""
        config = PromptFenceConfig(
            trusted_prefix="",
            trusted_suffix="",
        )

        assert config.trusted_prefix == ""
        assert config.trusted_suffix == ""

    def test_metadata_flags(self):
        """Should handle metadata inclusion flags."""
        config = PromptFenceConfig(
            include_metadata=False,
            include_trust_level=False,
            include_source_type=False,
        )

        assert config.include_metadata is False
        assert config.include_trust_level is False
        assert config.include_source_type is False


class TestLoggingConfig:
    """Tests for LoggingConfig validation and edge cases."""

    def test_default_config_values(self):
        """Default config should have expected values."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.redact_content is True
        assert config.max_logged_content_length == 200

    def test_valid_log_levels(self):
        """Should accept valid log levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_max_logged_content_length_boundaries(self):
        """Should handle max logged content length edge cases."""
        # Very short
        config = LoggingConfig(max_logged_content_length=1)
        assert config.max_logged_content_length == 1

        # Very long
        config = LoggingConfig(max_logged_content_length=10000)
        assert config.max_logged_content_length == 10000

        # Zero
        config = LoggingConfig(max_logged_content_length=0)
        assert config.max_logged_content_length == 0

    def test_all_logging_disabled(self):
        """Should allow disabling all logging."""
        config = LoggingConfig(
            enabled=False,
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.enabled is False
        assert config.log_detections is False


class TestMasterConfig:
    """Tests for master Config class."""

    def test_default_config(self):
        """Default config should initialize all sub-configs."""
        config = Config.default()

        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None
        assert config.fail_open is False
        assert config.strict_mode is False

    def test_strict_config(self):
        """Strict config should have more restrictive settings."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.5
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config(self):
        """Permissive config should have more lenient settings."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold == 0.85
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_custom_config_with_overrides(self):
        """Should allow custom config with overridden sub-configs."""
        custom_detector = DetectorConfig(
            confidence_threshold=0.6,
            use_ml_model=False,
        )

        config = Config(detector=custom_detector)

        assert config.detector.confidence_threshold == 0.6
        assert config.detector.use_ml_model is False

    def test_performance_settings(self):
        """Should accept performance configuration."""
        config = Config(
            enable_caching=False,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=10.0,
        )

        assert config.enable_caching is False
        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 10.0

    def test_cache_ttl_boundary_values(self):
        """Should handle cache TTL edge cases."""
        # Very short TTL
        config = Config(cache_ttl_seconds=1)
        assert config.cache_ttl_seconds == 1

        # Very long TTL
        config = Config(cache_ttl_seconds=86400)  # 1 day
        assert config.cache_ttl_seconds == 86400

        # Zero TTL (effectively no caching)
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_timeout_boundary_values(self):
        """Should handle timeout edge cases."""
        # Very short timeout
        config = Config(request_timeout_seconds=0.1)
        assert config.request_timeout_seconds == 0.1

        # Very long timeout
        config = Config(request_timeout_seconds=300.0)
        assert config.request_timeout_seconds == 300.0

    def test_risk_threshold_settings(self):
        """Should accept risk threshold configuration."""
        config = Config(
            block_threshold=RiskLevel.CRITICAL,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.block_threshold == RiskLevel.CRITICAL
        assert config.warn_threshold == RiskLevel.LOW

    def test_max_concurrent_requests_edge_cases(self):
        """Should handle concurrent request limits."""
        # Very low limit
        config = Config(max_concurrent_requests=1)
        assert config.max_concurrent_requests == 1

        # High limit
        config = Config(max_concurrent_requests=1000)
        assert config.max_concurrent_requests == 1000


class TestConfigSerialization:
    """Tests for config serialization and deserialization."""

    def test_config_to_dict(self):
        """Should serialize config to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict

    def test_config_roundtrip(self):
        """Should roundtrip config through dict."""
        original = Config.default()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.fail_open == original.fail_open
        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold

    def test_partial_config_from_dict(self):
        """Should create config from partial dict."""
        partial_dict = {
            "fail_open": True,
            "detector": {
                "confidence_threshold": 0.8,
            },
        }

        config = Config(**partial_dict)

        assert config.fail_open is True
        assert config.detector.confidence_threshold == 0.8
        # Other fields should have defaults
        assert config.strict_mode is False


class TestConfigValidationEdgeCases:
    """Tests for edge cases in config validation."""

    def test_conflicting_fail_modes(self):
        """Should allow conflicting fail modes (logic handles precedence)."""
        # Both strict and fail_open enabled
        config = Config(
            strict_mode=True,
            fail_open=True,
        )

        # Configuration is valid, runtime decides precedence
        assert config.strict_mode is True
        assert config.fail_open is True

    def test_disabled_layers_with_strict_mode(self):
        """Should allow disabling layers even in strict mode."""
        config = Config(
            strict_mode=True,
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
        )

        assert config.strict_mode is True
        assert config.trusted_filter.enabled is False
        assert config.data_filter.enabled is False
        assert config.detector.enabled is False

    def test_zero_confidence_threshold_with_strict_mode(self):
        """Should allow zero confidence threshold even in strict mode."""
        config = Config(
            strict_mode=True,
            detector=DetectorConfig(confidence_threshold=0.0),
        )

        assert config.strict_mode is True
        assert config.detector.confidence_threshold == 0.0

    def test_extreme_sensitivity_values(self):
        """Should handle extreme sensitivity multipliers."""
        config = Config(
            detector=DetectorConfig(
                tool_output_sensitivity=10.0,  # Very high
                pattern_confidence_boost=0.9,  # Very high boost
            ),
        )

        assert config.detector.tool_output_sensitivity == 10.0
        assert config.detector.pattern_confidence_boost == 0.9
