"""
Unit tests for configuration classes.

Tests the Config class and its nested configuration models to ensure
proper defaults, validation, and preset modes work correctly.
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
    """Tests for TrustedFilterConfig."""

    def test_default_values(self):
        """Should have sensible defaults for OSS projects."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external is True
        assert config.allow_anonymous is False
        assert config.filter_issue_content is True
        assert config.filter_comments is True

    def test_custom_allowlists(self):
        """Should accept custom allowed and blocked users."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            blocked_users=["eve"],
            allowed_domains=["trusted.com"],
            blocked_domains=["evil.com"],
        )

        assert "alice" in config.allowed_users
        assert "eve" in config.blocked_users
        assert "trusted.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains

    def test_strict_trust_settings(self):
        """Should allow strict trust configuration."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.MAINTAINER,
            allow_external=False,
            allow_anonymous=False,
        )

        assert config.minimum_trust_level == TrustLevel.MAINTAINER
        assert config.allow_external is False
        assert config.allow_anonymous is False


class TestDataFilterConfig:
    """Tests for DataFilterConfig."""

    def test_default_values(self):
        """Should have balanced defaults."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.remove_instructions is True
        assert config.remove_code_blocks is False  # Preserve code
        assert config.preserve_code_context is True

    def test_aggressiveness_levels(self):
        """Should support different aggressiveness levels."""
        minimal = DataFilterConfig(aggressiveness="minimal")
        balanced = DataFilterConfig(aggressiveness="balanced")
        aggressive = DataFilterConfig(aggressiveness="aggressive")

        assert minimal.aggressiveness == "minimal"
        assert balanced.aggressiveness == "balanced"
        assert aggressive.aggressiveness == "aggressive"

    def test_sanitization_modes(self):
        """Should support different sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_max_content_length(self):
        """Should have reasonable size limit."""
        config = DataFilterConfig()
        assert config.max_content_length == 100000

        # Should accept custom limit
        custom = DataFilterConfig(max_content_length=50000)
        assert custom.max_content_length == 50000

    def test_custom_removal_patterns(self):
        """Should accept custom regex patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"SECRET_\w+", r"PASSWORD:\s*\S+"]
        )

        assert len(config.custom_removal_patterns) == 2
        assert r"SECRET_\w+" in config.custom_removal_patterns


class TestDetectorConfig:
    """Tests for DetectorConfig."""

    def test_default_values(self):
        """Should have balanced detection defaults."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.confidence_threshold == 0.7
        assert config.min_risk_level == RiskLevel.LOW
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.context_aware is True

    def test_confidence_threshold_valid_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid values
        for threshold in [0.0, 0.5, 0.7, 0.85, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_ml_model_settings(self):
        """Should have ML model configuration."""
        config = DetectorConfig()

        assert config.ml_model_name == "microsoft/deberta-v3-base"
        assert config.ml_batch_size == 8
        assert config.ml_max_length == 512

        # Should accept custom settings
        custom = DetectorConfig(
            ml_model_name="custom/model",
            ml_batch_size=16,
            ml_max_length=256,
        )
        assert custom.ml_model_name == "custom/model"
        assert custom.ml_batch_size == 16

    def test_tool_output_sensitivity(self):
        """Should have higher sensitivity for tool outputs."""
        config = DetectorConfig()
        assert config.tool_output_sensitivity == 1.2

        # Should accept custom multiplier
        custom = DetectorConfig(tool_output_sensitivity=1.5)
        assert custom.tool_output_sensitivity == 1.5

    def test_false_positive_control(self):
        """Should allow legitimate code and docs by default."""
        config = DetectorConfig()

        assert config.allow_code_instructions is True
        assert config.allow_documentation_examples is True

    def test_custom_patterns(self):
        """Should accept custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_attack": r"malicious\s+pattern",
            },
            blocked_patterns=["known_bad_pattern"],
        )

        assert "custom_attack" in config.custom_patterns
        assert len(config.blocked_patterns) == 1


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig."""

    def test_default_values(self):
        """Should have secure defaults."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"
        assert config.include_metadata is True

    def test_fence_formats(self):
        """Should support different fence formats."""
        for format_type in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=format_type)
            assert config.fence_format == format_type

    def test_custom_delimiters(self):
        """Should accept custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="[SAFE]",
            trusted_suffix="[/SAFE]",
            untrusted_prefix="[UNSAFE]",
            untrusted_suffix="[/UNSAFE]",
        )

        assert config.trusted_prefix == "[SAFE]"
        assert config.trusted_suffix == "[/SAFE]"
        assert config.untrusted_prefix == "[UNSAFE]"
        assert config.untrusted_suffix == "[/UNSAFE]"

    def test_metadata_inclusion(self):
        """Should control metadata inclusion."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )

        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True


class TestLoggingConfig:
    """Tests for LoggingConfig."""

    def test_default_values(self):
        """Should have logging enabled with INFO level."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.log_detections is True
        assert config.log_sanitizations is True
        assert config.redact_content is True

    def test_log_levels(self):
        """Should support different log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_content_redaction(self):
        """Should redact sensitive content in logs."""
        config = LoggingConfig()

        assert config.redact_content is True
        assert config.max_logged_content_length == 200


class TestConfigPresets:
    """Tests for Config preset modes."""

    def test_default_config(self):
        """Default config should be balanced."""
        config = Config.default()

        assert config.fail_open is False
        assert config.strict_mode is False
        assert config.trusted_filter.allow_external is True
        assert config.detector.confidence_threshold == 0.7
        assert config.block_threshold == RiskLevel.HIGH

    def test_strict_config(self):
        """Strict config should be more secure."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_external is False
        assert config.trusted_filter.allow_anonymous is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.5  # Lower = more detections
        assert config.detector.tool_output_sensitivity == 1.5
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config(self):
        """Permissive config should reduce false positives."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold == 0.85  # Higher = fewer detections
        assert config.detector.tool_output_sensitivity == 1.0
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_strict_vs_permissive_differences(self):
        """Strict should be more restrictive than permissive."""
        strict = Config.strict()
        permissive = Config.permissive()

        # Trust settings
        assert strict.trusted_filter.minimum_trust_level > permissive.trusted_filter.minimum_trust_level
        assert strict.trusted_filter.allow_external is False
        assert permissive.trusted_filter.allow_external is True

        # Detection thresholds
        assert strict.detector.confidence_threshold < permissive.detector.confidence_threshold
        assert strict.block_threshold < permissive.block_threshold

        # Fail open behavior
        assert strict.fail_open is False
        assert permissive.fail_open is True


class TestConfigCustomization:
    """Tests for custom Config creation."""

    def test_custom_config(self):
        """Should create config with custom settings."""
        config = Config(
            strict_mode=True,
            fail_open=False,
            block_threshold=RiskLevel.MEDIUM,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.block_threshold == RiskLevel.MEDIUM
        assert config.warn_threshold == RiskLevel.LOW

    def test_nested_config_customization(self):
        """Should customize nested configurations."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.MAINTAINER,
                allowed_users=["admin"],
            ),
            detector=DetectorConfig(
                confidence_threshold=0.8,
                use_ml_model=False,
            ),
        )

        assert config.trusted_filter.minimum_trust_level == TrustLevel.MAINTAINER
        assert "admin" in config.trusted_filter.allowed_users
        assert config.detector.confidence_threshold == 0.8
        assert config.detector.use_ml_model is False

    def test_performance_settings(self):
        """Should have performance configuration."""
        config = Config()

        assert config.enable_caching is True
        assert config.cache_ttl_seconds == 3600
        assert config.max_concurrent_requests == 100
        assert config.request_timeout_seconds == 30.0

        # Should accept custom values
        custom = Config(
            enable_caching=False,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=60.0,
        )
        assert custom.enable_caching is False
        assert custom.cache_ttl_seconds == 7200
        assert custom.max_concurrent_requests == 50
        assert custom.request_timeout_seconds == 60.0


class TestConfigValidation:
    """Tests for config validation and edge cases."""

    def test_confidence_threshold_boundaries(self):
        """Confidence threshold edge cases."""
        # Should accept boundary values
        config_0 = DetectorConfig(confidence_threshold=0.0)
        config_1 = DetectorConfig(confidence_threshold=1.0)

        assert config_0.confidence_threshold == 0.0
        assert config_1.confidence_threshold == 1.0

    def test_empty_custom_patterns(self):
        """Should handle empty custom patterns."""
        config = DetectorConfig(
            custom_patterns={},
            blocked_patterns=[],
        )

        assert len(config.custom_patterns) == 0
        assert len(config.blocked_patterns) == 0

    def test_config_serialization(self):
        """Config should be serializable to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict

    def test_config_from_dict(self):
        """Should create config from dictionary."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
            "trusted_filter": {
                "minimum_trust_level": "developer",
                "allow_external": False,
            },
            "detector": {
                "confidence_threshold": 0.6,
            },
        }

        config = Config(**config_dict)

        assert config.strict_mode is True
        assert config.trusted_filter.allow_external is False
        assert config.detector.confidence_threshold == 0.6


class TestConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_all_layers_disabled(self):
        """Should allow disabling all layers (for testing)."""
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

    def test_max_content_length_zero(self):
        """Should handle edge case of zero max length."""
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0

    def test_very_high_sensitivity(self):
        """Should accept very high sensitivity multipliers."""
        config = DetectorConfig(tool_output_sensitivity=5.0)
        assert config.tool_output_sensitivity == 5.0

    def test_multiple_preset_modifications(self):
        """Should allow modifying presets."""
        strict = Config.strict()

        # Modify strict config
        strict.fail_open = True
        strict.detector.confidence_threshold = 0.75

        assert strict.fail_open is True
        assert strict.detector.confidence_threshold == 0.75
        # Other strict settings should remain
        assert strict.strict_mode is True
