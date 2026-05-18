"""
Unit tests for configuration validation and edge cases.

Tests the Config system's validation, edge cases, and preset configurations.
"""

import json
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


class TestConfigPresets:
    """Tests for preset configurations."""

    def test_default_config_valid(self):
        """Default config should be valid and instantiable."""
        config = Config.default()

        assert config is not None
        assert config.trusted_filter.enabled is True
        assert config.detector.enabled is True
        assert config.fail_open is False

    def test_strict_config_valid(self):
        """Strict config should be valid and more restrictive."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False
        assert config.detector.confidence_threshold < 0.7  # Lower threshold = stricter
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_valid(self):
        """Permissive config should be valid and more lenient."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.detector.confidence_threshold > 0.7  # Higher threshold = less sensitive
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_presets_are_distinct(self):
        """Each preset should have different settings."""
        default = Config.default()
        strict = Config.strict()
        permissive = Config.permissive()

        # Strict should be more restrictive than default
        # RiskLevel ordering: NONE < LOW < MEDIUM < HIGH < CRITICAL
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(strict.block_threshold) < risk_order.index(default.block_threshold)
        assert strict.trusted_filter.allow_external is False

        # Permissive should be less restrictive than default
        assert risk_order.index(permissive.block_threshold) > risk_order.index(default.block_threshold)
        assert permissive.fail_open is True


class TestDetectorConfigValidation:
    """Tests for detector configuration validation."""

    def test_valid_confidence_threshold(self):
        """Confidence threshold should accept values between 0 and 1."""
        # Valid values
        DetectorConfig(confidence_threshold=0.0)
        DetectorConfig(confidence_threshold=0.5)
        DetectorConfig(confidence_threshold=1.0)

    def test_confidence_threshold_bounds(self):
        """Confidence threshold should be bounded 0-1."""
        # Note: Pydantic doesn't enforce bounds by default unless we add validators
        # This test documents expected behavior
        config = DetectorConfig(confidence_threshold=1.5)
        # If validation is added, this should raise ValidationError
        # For now, we just verify it creates the config
        assert config.confidence_threshold == 1.5

    def test_custom_patterns_dict(self):
        """Custom patterns should accept dict of name->regex."""
        custom = {
            "test_pattern": r"test\s+pattern",
            "another_pattern": r"(?:abc|def)",
        }
        config = DetectorConfig(custom_patterns=custom)

        assert config.custom_patterns == custom
        assert "test_pattern" in config.custom_patterns

    def test_empty_custom_patterns(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_blocked_patterns_list(self):
        """Blocked patterns should accept list of strings."""
        blocked = ["pattern1", "pattern2", "pattern3"]
        config = DetectorConfig(blocked_patterns=blocked)

        assert config.blocked_patterns == blocked
        assert len(config.blocked_patterns) == 3

    def test_disable_all_detection_methods(self):
        """Should allow disabling all detection methods (edge case)."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        # Valid config but probably ineffective
        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_tool_output_sensitivity_multiplier(self):
        """Tool output sensitivity should accept valid multipliers."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

        # Zero sensitivity (edge case)
        config_zero = DetectorConfig(tool_output_sensitivity=0.0)
        assert config_zero.tool_output_sensitivity == 0.0


class TestTrustedFilterConfigValidation:
    """Tests for trusted filter configuration validation."""

    def test_allowed_users_list(self):
        """Allowed users should accept list of usernames."""
        users = ["alice", "bob", "charlie"]
        config = TrustedFilterConfig(allowed_users=users)

        assert config.allowed_users == users
        assert "alice" in config.allowed_users

    def test_blocked_users_list(self):
        """Blocked users should accept list of usernames."""
        users = ["malicious1", "malicious2"]
        config = TrustedFilterConfig(blocked_users=users)

        assert config.blocked_users == users

    def test_allowed_and_blocked_domains(self):
        """Should accept both allowed and blocked domain lists."""
        config = TrustedFilterConfig(
            allowed_domains=["example.com", "trusted.org"],
            blocked_domains=["evil.com", "spam.net"],
        )

        assert len(config.allowed_domains) == 2
        assert len(config.blocked_domains) == 2

    def test_conflicting_allow_settings(self):
        """Should handle conflicting allow settings (edge case)."""
        # This is an edge case: allow_external=False but allow_anonymous=True
        # Anonymous is typically less trusted than external
        config = TrustedFilterConfig(
            allow_external=False,
            allow_anonymous=True,  # Conflicting!
        )

        # Config is created, but logic may need to handle this
        assert config.allow_external is False
        assert config.allow_anonymous is True

    def test_empty_allowlists_and_blocklists(self):
        """Empty lists should be valid (no restrictions)."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
            allowed_domains=[],
            blocked_domains=[],
        )

        assert config.allowed_users == []
        assert config.blocked_users == []


class TestDataFilterConfigValidation:
    """Tests for data filter configuration validation."""

    def test_valid_modes(self):
        """Should accept valid sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_invalid_mode(self):
        """Should handle invalid mode (no validation enforced by default)."""
        config = DataFilterConfig(mode="invalid_mode")
        # Pydantic doesn't validate enum-like string unless we add validator
        assert config.mode == "invalid_mode"

    def test_valid_aggressiveness_levels(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_boundary(self):
        """Max content length should accept various values."""
        # Very small
        config_small = DataFilterConfig(max_content_length=1)
        assert config_small.max_content_length == 1

        # Very large
        config_large = DataFilterConfig(max_content_length=10_000_000)
        assert config_large.max_content_length == 10_000_000

        # Zero (edge case)
        config_zero = DataFilterConfig(max_content_length=0)
        assert config_zero.max_content_length == 0

    def test_custom_removal_patterns_list(self):
        """Custom removal patterns should accept regex list."""
        patterns = [
            r"DELETE\s+FROM",
            r"DROP\s+TABLE",
            r"EXEC\s*\(",
        ]
        config = DataFilterConfig(custom_removal_patterns=patterns)

        assert config.custom_removal_patterns == patterns
        assert len(config.custom_removal_patterns) == 3

    def test_all_removal_options_disabled(self):
        """Should allow disabling all removal options (edge case)."""
        config = DataFilterConfig(
            remove_instructions=False,
            remove_code_blocks=False,
            remove_urls=False,
            remove_email_addresses=False,
            custom_removal_patterns=[],
        )

        # Valid but ineffective config
        assert config.remove_instructions is False
        assert config.remove_code_blocks is False


class TestPromptFenceConfigValidation:
    """Tests for prompt fence configuration validation."""

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_custom_delimiters(self):
        """Should accept custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="[[[TRUSTED]]]",
            trusted_suffix="[[[/TRUSTED]]]",
            untrusted_prefix="[[[UNTRUSTED]]]",
            untrusted_suffix="[[[/UNTRUSTED]]]",
        )

        assert config.trusted_prefix == "[[[TRUSTED]]]"
        assert config.untrusted_suffix == "[[[/UNTRUSTED]]]"

    def test_empty_delimiters(self):
        """Empty delimiters should be accepted (edge case)."""
        config = PromptFenceConfig(
            trusted_prefix="",
            trusted_suffix="",
        )

        assert config.trusted_prefix == ""
        assert config.trusted_suffix == ""

    def test_signature_settings(self):
        """Should accept signature configuration."""
        config = PromptFenceConfig(
            use_signatures=True,
            signature_algorithm="hmac-sha256",
        )

        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"

    def test_metadata_flags(self):
        """Should accept metadata inclusion flags."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )

        assert config.include_metadata is True
        assert config.include_trust_level is True


class TestLoggingConfigValidation:
    """Tests for logging configuration validation."""

    def test_valid_log_levels(self):
        """Should accept common log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_max_logged_content_length(self):
        """Max logged content length should accept various values."""
        config = LoggingConfig(max_logged_content_length=500)
        assert config.max_logged_content_length == 500

        # Zero length (edge case - no content logged)
        config_zero = LoggingConfig(max_logged_content_length=0)
        assert config_zero.max_logged_content_length == 0

    def test_redaction_settings(self):
        """Should accept redaction settings."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100,
        )

        assert config.redact_content is True
        assert config.max_logged_content_length == 100

    def test_disable_all_logging(self):
        """Should allow disabling all logging (edge case)."""
        config = LoggingConfig(
            enabled=False,
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.enabled is False
        assert config.log_detections is False


class TestMasterConfigValidation:
    """Tests for master Config validation."""

    def test_nested_config_structure(self):
        """Config should properly nest all sub-configs."""
        config = Config()

        assert isinstance(config.trusted_filter, TrustedFilterConfig)
        assert isinstance(config.data_filter, DataFilterConfig)
        assert isinstance(config.detector, DetectorConfig)
        assert isinstance(config.prompt_fence, PromptFenceConfig)
        assert isinstance(config.logging, LoggingConfig)

    def test_custom_nested_configs(self):
        """Should accept custom nested configurations."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allowed_users=["alice", "bob"],
            ),
            detector=DetectorConfig(
                confidence_threshold=0.9,
            ),
        )

        assert "alice" in config.trusted_filter.allowed_users
        assert config.detector.confidence_threshold == 0.9

    def test_performance_settings(self):
        """Performance settings should accept valid values."""
        config = Config(
            enable_caching=True,
            cache_ttl_seconds=7200,
            max_concurrent_requests=200,
            request_timeout_seconds=60.0,
        )

        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 200
        assert config.request_timeout_seconds == 60.0

    def test_zero_timeout(self):
        """Zero timeout should be accepted (edge case)."""
        config = Config(request_timeout_seconds=0.0)
        assert config.request_timeout_seconds == 0.0

    def test_negative_timeout(self):
        """Negative timeout should be accepted (no validation)."""
        config = Config(request_timeout_seconds=-1.0)
        # Should probably be validated, but isn't by default
        assert config.request_timeout_seconds == -1.0

    def test_risk_level_thresholds(self):
        """Risk level thresholds should accept valid RiskLevel values."""
        config = Config(
            block_threshold=RiskLevel.MEDIUM,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.block_threshold == RiskLevel.MEDIUM
        assert config.warn_threshold == RiskLevel.LOW

    def test_inverted_thresholds(self):
        """Should handle inverted thresholds (edge case)."""
        # Warn threshold higher than block threshold (unusual but allowed)
        config = Config(
            block_threshold=RiskLevel.LOW,
            warn_threshold=RiskLevel.HIGH,
        )

        assert config.block_threshold == RiskLevel.LOW
        assert config.warn_threshold == RiskLevel.HIGH

    def test_fail_open_vs_strict_mode(self):
        """Should handle both fail_open and strict_mode flags."""
        # Both False (default secure)
        config1 = Config(fail_open=False, strict_mode=False)
        assert config1.fail_open is False

        # Both True (conflicting but allowed)
        config2 = Config(fail_open=True, strict_mode=True)
        assert config2.fail_open is True
        assert config2.strict_mode is True


class TestConfigSerialization:
    """Tests for config serialization/deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Config should deserialize from dict."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
            "detector": {
                "confidence_threshold": 0.8,
            },
        }

        config = Config(**config_dict)

        assert config.strict_mode is True
        assert config.detector.confidence_threshold == 0.8

    def test_config_to_json(self):
        """Config should serialize to JSON."""
        config = Config.default()
        json_str = config.model_dump_json()

        assert isinstance(json_str, str)

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_config_from_json(self):
        """Config should deserialize from JSON."""
        json_str = '{"strict_mode": true, "fail_open": false}'
        config_dict = json.loads(json_str)
        config = Config(**config_dict)

        assert config.strict_mode is True
        assert config.fail_open is False

    def test_roundtrip_serialization(self):
        """Config should roundtrip through JSON."""
        original = Config.strict()

        # To JSON and back
        json_str = original.model_dump_json()
        config_dict = json.loads(json_str)
        restored = Config(**config_dict)

        # Should match
        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold
        assert restored.trusted_filter.allow_external == original.trusted_filter.allow_external

    def test_partial_config_dict(self):
        """Should handle partial config dict with defaults."""
        partial = {
            "strict_mode": True,
        }

        config = Config(**partial)

        # Specified value
        assert config.strict_mode is True
        # Default values for unspecified
        assert config.trusted_filter is not None
        assert config.detector is not None


class TestConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_config_uses_defaults(self):
        """Empty config should use all defaults."""
        config = Config()

        assert config.fail_open is False
        assert config.strict_mode is False
        assert config.detector.enabled is True

    def test_disable_all_layers(self):
        """Should allow disabling all layers (edge case)."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False),
        )

        # All layers disabled
        assert config.trusted_filter.enabled is False
        assert config.data_filter.enabled is False
        assert config.detector.enabled is False
        assert config.prompt_fence.enabled is False

    def test_extreme_cache_ttl(self):
        """Should handle extreme cache TTL values."""
        # Very short TTL
        config_short = Config(cache_ttl_seconds=1)
        assert config_short.cache_ttl_seconds == 1

        # Very long TTL (1 year)
        config_long = Config(cache_ttl_seconds=31536000)
        assert config_long.cache_ttl_seconds == 31536000

    def test_max_concurrent_requests_limits(self):
        """Should handle various concurrent request limits."""
        # Single request
        config_one = Config(max_concurrent_requests=1)
        assert config_one.max_concurrent_requests == 1

        # Very high
        config_high = Config(max_concurrent_requests=10000)
        assert config_high.max_concurrent_requests == 10000

    def test_all_trust_levels(self):
        """Should accept all valid trust levels."""
        for level in TrustLevel:
            config = TrustedFilterConfig(minimum_trust_level=level)
            assert config.minimum_trust_level == level

    def test_all_risk_levels(self):
        """Should accept all valid risk levels."""
        for level in RiskLevel:
            config = Config(block_threshold=level)
            assert config.block_threshold == level
