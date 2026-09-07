"""
Unit tests for configuration validation.

Tests configuration edge cases, validation, and security-critical settings.
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
    """Tests for TrustedFilterConfig validation."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external is True
        assert isinstance(config.allowed_users, list)

    def test_trust_level_validation(self):
        """Trust level should accept valid enum values."""
        config = TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)

        assert config.minimum_trust_level == TrustLevel.DEVELOPER

    def test_allowlist_blocklist_configuration(self):
        """Should support custom allow/block lists."""
        config = TrustedFilterConfig(
            allowed_users=["user1", "user2"],
            blocked_users=["attacker"],
            allowed_domains=["trusted.com"],
            blocked_domains=["evil.com"],
        )

        assert "user1" in config.allowed_users
        assert "attacker" in config.blocked_users
        assert "trusted.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains

    def test_empty_lists_are_valid(self):
        """Empty lists should be valid for allow/block lists."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
        )

        assert config.allowed_users == []
        assert config.blocked_users == []

    def test_disabled_filter(self):
        """Filter can be disabled."""
        config = TrustedFilterConfig(enabled=False)

        assert config.enabled is False


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.max_content_length == 100000

    def test_valid_sanitization_modes(self):
        """Should accept valid sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness_levels(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_validation(self):
        """Max content length should accept positive integers."""
        config = DataFilterConfig(max_content_length=50000)

        assert config.max_content_length == 50000

    def test_max_content_length_zero(self):
        """Zero max content length should be accepted (no limit)."""
        config = DataFilterConfig(max_content_length=0)

        assert config.max_content_length == 0

    def test_custom_removal_patterns(self):
        """Should accept custom regex patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"\[SECRET\].*?\[/SECRET\]", r"API_KEY:\s*\S+"]
        )

        assert len(config.custom_removal_patterns) == 2
        assert r"\[SECRET\]" in config.custom_removal_patterns[0]

    def test_boolean_flags(self):
        """Should accept boolean flags for various settings."""
        config = DataFilterConfig(
            remove_instructions=False,
            remove_code_blocks=True,
            remove_urls=True,
            preserve_code_context=False,
        )

        assert config.remove_instructions is False
        assert config.remove_code_blocks is True
        assert config.remove_urls is True
        assert config.preserve_code_context is False


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.confidence_threshold == 0.7
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True

    def test_confidence_threshold_valid_range(self):
        """Confidence threshold should accept values between 0 and 1."""
        for threshold in [0.0, 0.3, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_confidence_threshold_boundary_values(self):
        """Should accept boundary values for confidence threshold."""
        config_min = DetectorConfig(confidence_threshold=0.0)
        config_max = DetectorConfig(confidence_threshold=1.0)

        assert config_min.confidence_threshold == 0.0
        assert config_max.confidence_threshold == 1.0

    def test_risk_level_validation(self):
        """Min risk level should accept valid enum values."""
        for risk_level in [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            config = DetectorConfig(min_risk_level=risk_level)
            assert config.min_risk_level == risk_level

    def test_detector_components_toggle(self):
        """Should allow toggling detector components."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=True,
        )

        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is True

    def test_all_detectors_disabled(self):
        """Should allow all detectors to be disabled (though not recommended)."""
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
            ml_model_name="custom-model",
            ml_batch_size=16,
            ml_max_length=256,
        )

        assert config.ml_model_name == "custom-model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_sensitivity_multiplier(self):
        """Tool output sensitivity should accept positive floats."""
        config = DetectorConfig(tool_output_sensitivity=1.5)

        assert config.tool_output_sensitivity == 1.5

    def test_sensitivity_boundary_values(self):
        """Should accept various sensitivity values."""
        for sensitivity in [0.5, 1.0, 1.2, 2.0]:
            config = DetectorConfig(tool_output_sensitivity=sensitivity)
            assert config.tool_output_sensitivity == sensitivity

    def test_custom_patterns(self):
        """Should accept custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_exfil": r"send.*to.*external",
                "custom_backdoor": r"create.*backdoor",
            }
        )

        assert "custom_exfil" in config.custom_patterns
        assert len(config.custom_patterns) == 2

    def test_blocked_patterns(self):
        """Should accept list of blocked patterns."""
        config = DetectorConfig(
            blocked_patterns=["ignore all instructions", "bypass security"]
        )

        assert len(config.blocked_patterns) == 2


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        for format in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=format)
            assert config.fence_format == format

    def test_signature_settings(self):
        """Should accept signature configuration."""
        config = PromptFenceConfig(
            use_signatures=False,
            signature_algorithm="hmac-sha512",
        )

        assert config.use_signatures is False
        assert config.signature_algorithm == "hmac-sha512"

    def test_custom_delimiters(self):
        """Should accept custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="[TRUSTED]",
            trusted_suffix="[/TRUSTED]",
            untrusted_prefix="[UNTRUSTED]",
            untrusted_suffix="[/UNTRUSTED]",
        )

        assert config.trusted_prefix == "[TRUSTED]"
        assert config.trusted_suffix == "[/TRUSTED]"

    def test_metadata_flags(self):
        """Should accept metadata inclusion flags."""
        config = PromptFenceConfig(
            include_metadata=False,
            include_trust_level=False,
            include_source_type=False,
        )

        assert config.include_metadata is False
        assert config.include_trust_level is False


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.redact_content is True

    def test_valid_log_levels(self):
        """Should accept valid log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_flags(self):
        """Should accept various logging flags."""
        config = LoggingConfig(
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.log_detections is False
        assert config.log_sanitizations is False

    def test_content_redaction(self):
        """Should accept content redaction settings."""
        config = LoggingConfig(
            redact_content=False,
            max_logged_content_length=500,
        )

        assert config.redact_content is False
        assert config.max_logged_content_length == 500


class TestMasterConfig:
    """Tests for master Config class."""

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = Config()

        assert config.fail_open is False
        assert config.strict_mode is False
        assert isinstance(config.trusted_filter, TrustedFilterConfig)
        assert isinstance(config.detector, DetectorConfig)

    def test_default_class_method(self):
        """Config.default() should return default config."""
        config = Config.default()

        assert config.fail_open is False
        assert config.block_threshold == RiskLevel.HIGH

    def test_strict_class_method(self):
        """Config.strict() should return strict config."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_external is False
        assert config.detector.confidence_threshold == 0.5
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_class_method(self):
        """Config.permissive() should return permissive config."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.detector.confidence_threshold == 0.85
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_global_settings(self):
        """Should accept global settings."""
        config = Config(
            fail_open=True,
            strict_mode=True,
        )

        assert config.fail_open is True
        assert config.strict_mode is True

    def test_performance_settings(self):
        """Should accept performance settings."""
        config = Config(
            enable_caching=False,
            cache_ttl_seconds=1800,
            max_concurrent_requests=50,
            request_timeout_seconds=15.0,
        )

        assert config.enable_caching is False
        assert config.cache_ttl_seconds == 1800
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 15.0

    def test_risk_thresholds(self):
        """Should accept risk threshold configuration."""
        config = Config(
            block_threshold=RiskLevel.MEDIUM,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.block_threshold == RiskLevel.MEDIUM
        assert config.warn_threshold == RiskLevel.LOW

    def test_nested_config_override(self):
        """Should allow overriding nested configs."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.ADMIN,
                allow_external=False,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.9,
                use_ml_model=False,
            ),
        )

        assert config.trusted_filter.minimum_trust_level == TrustLevel.ADMIN
        assert config.trusted_filter.allow_external is False
        assert config.detector.confidence_threshold == 0.9
        assert config.detector.use_ml_model is False


class TestConfigEdgeCases:
    """Tests for configuration edge cases."""

    def test_extreme_confidence_threshold(self):
        """Should handle extreme but valid confidence thresholds."""
        config_paranoid = DetectorConfig(confidence_threshold=0.99)
        config_lenient = DetectorConfig(confidence_threshold=0.01)

        assert config_paranoid.confidence_threshold == 0.99
        assert config_lenient.confidence_threshold == 0.01

    def test_zero_cache_ttl(self):
        """Zero cache TTL should be valid (no caching)."""
        config = Config(cache_ttl_seconds=0)

        assert config.cache_ttl_seconds == 0

    def test_very_large_content_limit(self):
        """Should accept very large content limits."""
        config = DataFilterConfig(max_content_length=10_000_000)

        assert config.max_content_length == 10_000_000

    def test_timeout_boundary_values(self):
        """Should accept various timeout values."""
        config_fast = Config(request_timeout_seconds=1.0)
        config_slow = Config(request_timeout_seconds=120.0)

        assert config_fast.request_timeout_seconds == 1.0
        assert config_slow.request_timeout_seconds == 120.0

    def test_concurrent_requests_limits(self):
        """Should accept various concurrency limits."""
        config_low = Config(max_concurrent_requests=1)
        config_high = Config(max_concurrent_requests=1000)

        assert config_low.max_concurrent_requests == 1
        assert config_high.max_concurrent_requests == 1000

    def test_empty_custom_patterns(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(custom_patterns={})

        assert config.custom_patterns == {}

    def test_multiple_custom_patterns(self):
        """Should handle many custom patterns."""
        patterns = {f"pattern_{i}": f"regex_{i}" for i in range(50)}
        config = DetectorConfig(custom_patterns=patterns)

        assert len(config.custom_patterns) == 50


class TestConfigSerialization:
    """Tests for configuration serialization/deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dict."""
        config = Config()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Config should deserialize from dict."""
        config_dict = {
            "fail_open": True,
            "strict_mode": False,
            "detector": {
                "confidence_threshold": 0.8,
            },
        }

        config = Config(**config_dict)

        assert config.fail_open is True
        assert config.detector.confidence_threshold == 0.8

    def test_partial_config_dict(self):
        """Should handle partial config dicts with defaults."""
        config_dict = {
            "fail_open": True,
        }

        config = Config(**config_dict)

        assert config.fail_open is True
        assert config.detector.confidence_threshold == 0.7  # Default
