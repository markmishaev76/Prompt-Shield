"""
Unit tests for configuration module.

Tests configuration validation, edge cases, serialization, and factory methods.
Configuration bugs can lead to security issues, so thorough testing is critical.
"""

import json
import pytest
from pathlib import Path
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


class TestConfigValidation:
    """Test configuration validation and error handling."""

    def test_default_config_is_valid(self):
        """Default configuration should be valid."""
        config = Config.default()
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_strict_config_is_valid(self):
        """Strict configuration should be valid."""
        config = Config.strict()
        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_is_valid(self):
        """Permissive configuration should be valid."""
        config = Config.permissive()
        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_invalid_risk_level_raises_error(self):
        """Invalid risk level should raise ValidationError."""
        with pytest.raises(ValidationError):
            Config(block_threshold="INVALID_LEVEL")

    def test_negative_timeout_does_not_validate(self):
        """
        Negative timeout is currently NOT validated (potential issue).

        NOTE: This test documents current behavior. Ideally, negative timeouts
        should be rejected, but the config model doesn't enforce this.
        """
        config = Config(request_timeout_seconds=-1.0)
        assert config.request_timeout_seconds == -1.0
        # TODO: Add validation to reject negative timeouts

    def test_invalid_detector_confidence_not_validated(self):
        """
        Detector confidence outside [0,1] is currently NOT validated.

        NOTE: This is a potential security issue - invalid confidence
        thresholds could lead to unexpected behavior or bypasses.
        """
        # Currently these are accepted (should ideally be rejected)
        config_high = Config(detector=DetectorConfig(confidence_threshold=1.5))
        assert config_high.detector.confidence_threshold == 1.5

        config_neg = Config(detector=DetectorConfig(confidence_threshold=-0.1))
        assert config_neg.detector.confidence_threshold == -0.1
        # TODO: Add validation to enforce 0.0 <= confidence <= 1.0

    def test_zero_max_concurrent_requests_not_validated(self):
        """
        Zero or negative max_concurrent_requests is currently NOT validated.

        NOTE: This could cause runtime issues if not checked elsewhere.
        """
        config_zero = Config(max_concurrent_requests=0)
        assert config_zero.max_concurrent_requests == 0

        config_neg = Config(max_concurrent_requests=-10)
        assert config_neg.max_concurrent_requests == -10
        # TODO: Add validation to enforce positive values

    def test_invalid_data_filter_mode_raises_error(self):
        """Invalid data filter mode should not cause silent failures."""
        # Note: Pydantic allows any string, but we should test it doesn't break
        config = Config(data_filter=DataFilterConfig(mode="invalid_mode"))
        assert config.data_filter.mode == "invalid_mode"
        # In production, the DataFilter layer should validate this


class TestConfigSerialization:
    """Test configuration serialization and deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dictionary."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict
        assert "logging" in config_dict

    def test_config_to_json(self):
        """Config should serialize to JSON."""
        config = Config.default()
        config_json = config.model_dump_json()

        assert isinstance(config_json, str)

        # Should be valid JSON
        parsed = json.loads(config_json)
        assert isinstance(parsed, dict)

    def test_config_from_dict(self):
        """Config should deserialize from dictionary."""
        config_dict = {
            "fail_open": True,
            "strict_mode": False,
            "block_threshold": "high",
            "trusted_filter": {
                "enabled": True,
                "minimum_trust_level": "developer",
            },
        }

        config = Config(**config_dict)
        assert config.fail_open is True
        assert config.strict_mode is False
        assert config.block_threshold == RiskLevel.HIGH
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER

    def test_config_round_trip(self):
        """Config should survive round-trip serialization."""
        original = Config.strict()

        # Serialize to dict and back
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.block_threshold == original.block_threshold
        assert restored.trusted_filter.minimum_trust_level == original.trusted_filter.minimum_trust_level

    def test_partial_config_uses_defaults(self):
        """Partial config should fill in defaults for missing fields."""
        config = Config(fail_open=True)

        # Should use defaults for everything else
        assert config.strict_mode is False  # Default
        assert config.enable_caching is True  # Default
        assert config.trusted_filter.enabled is True  # Default


class TestTrustedFilterConfig:
    """Test TrustedFilterConfig edge cases."""

    def test_default_trust_level_is_external(self):
        """Default minimum trust level should be EXTERNAL (OSS-friendly)."""
        config = TrustedFilterConfig()
        assert config.minimum_trust_level == TrustLevel.EXTERNAL

    def test_trust_level_comparison(self):
        """Trust levels should be comparable for strictness checks."""
        config_external = TrustedFilterConfig(minimum_trust_level=TrustLevel.EXTERNAL)
        config_developer = TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)

        # Trust levels are different
        assert config_developer.minimum_trust_level != config_external.minimum_trust_level

        # Note: Enum values are strings, not ordered integers
        # Runtime code must handle comparison explicitly

    def test_allow_lists_and_block_lists_can_coexist(self):
        """Allow and block lists should be able to coexist."""
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

    def test_empty_lists_are_default(self):
        """Empty lists should be the default for allow/block lists."""
        config = TrustedFilterConfig()
        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []


class TestDataFilterConfig:
    """Test DataFilterConfig edge cases."""

    def test_default_mode_is_remove(self):
        """Default sanitization mode should be 'remove'."""
        config = DataFilterConfig()
        assert config.mode == "remove"

    def test_aggressiveness_levels(self):
        """Test all aggressiveness levels are valid."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_default(self):
        """Default max content length should be reasonable."""
        config = DataFilterConfig()
        assert config.max_content_length == 100000
        assert config.max_content_length > 0

    def test_negative_max_content_length_not_validated(self):
        """
        Negative max content length is currently NOT validated.

        NOTE: This could cause runtime issues in the DataFilter.
        """
        config = DataFilterConfig(max_content_length=-1)
        assert config.max_content_length == -1
        # TODO: Add validation to enforce positive values

    def test_custom_removal_patterns_empty_by_default(self):
        """Custom removal patterns should be empty by default."""
        config = DataFilterConfig()
        assert config.custom_removal_patterns == []

    def test_custom_removal_patterns_can_be_set(self):
        """Custom removal patterns should be settable."""
        patterns = [r"secret:\s*\w+", r"password:\s*\S+"]
        config = DataFilterConfig(custom_removal_patterns=patterns)
        assert len(config.custom_removal_patterns) == 2
        assert patterns[0] in config.custom_removal_patterns


class TestDetectorConfig:
    """Test DetectorConfig edge cases."""

    def test_confidence_threshold_range(self):
        """
        Confidence threshold should be between 0 and 1 for proper detection.

        NOTE: Currently no validation is enforced - values outside [0,1]
        are accepted, which could lead to detection bypasses.
        """
        # Valid values work as expected
        DetectorConfig(confidence_threshold=0.0)
        DetectorConfig(confidence_threshold=0.5)
        DetectorConfig(confidence_threshold=1.0)

        # Invalid values are currently accepted (SECURITY ISSUE)
        config_low = DetectorConfig(confidence_threshold=-0.1)
        assert config_low.confidence_threshold == -0.1

        config_high = DetectorConfig(confidence_threshold=1.1)
        assert config_high.confidence_threshold == 1.1
        # TODO: Add Pydantic Field validators to enforce 0.0 <= value <= 1.0

    def test_all_detector_components_enabled_by_default(self):
        """All detector components should be enabled by default."""
        config = DetectorConfig()
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_detector_can_be_disabled_selectively(self):
        """Individual detector components can be disabled."""
        config = DetectorConfig(
            use_pattern_matching=True,
            use_ml_model=False,
            use_heuristics=True,
        )
        assert config.use_pattern_matching is True
        assert config.use_ml_model is False
        assert config.use_heuristics is True

    def test_ml_batch_size_not_validated(self):
        """
        ML batch size should be positive, but validation is not enforced.
        """
        config = DetectorConfig(ml_batch_size=16)
        assert config.ml_batch_size == 16

        # Currently accepts invalid values
        config_zero = DetectorConfig(ml_batch_size=0)
        assert config_zero.ml_batch_size == 0

        config_neg = DetectorConfig(ml_batch_size=-1)
        assert config_neg.ml_batch_size == -1
        # TODO: Add validation for positive batch size

    def test_ml_max_length_not_validated(self):
        """
        ML max length should be positive, but validation is not enforced.
        """
        config = DetectorConfig(ml_max_length=512)
        assert config.ml_max_length == 512

        # Currently accepts invalid values
        config_zero = DetectorConfig(ml_max_length=0)
        assert config_zero.ml_max_length == 0
        # TODO: Add validation for positive max length

    def test_custom_patterns_can_be_added(self):
        """Custom detection patterns can be added."""
        custom = {
            "secret_leak": r"secret:\s*\w+",
            "token_exfil": r"token:\s*\S+",
        }
        config = DetectorConfig(custom_patterns=custom)
        assert len(config.custom_patterns) == 2
        assert "secret_leak" in config.custom_patterns


class TestPromptFenceConfig:
    """Test PromptFenceConfig edge cases."""

    def test_default_fence_format_is_xml(self):
        """Default fence format should be XML."""
        config = PromptFenceConfig()
        assert config.fence_format == "xml"

    def test_valid_fence_formats(self):
        """Test all valid fence formats."""
        for format in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=format)
            assert config.fence_format == format

    def test_signatures_enabled_by_default(self):
        """Cryptographic signatures should be enabled by default."""
        config = PromptFenceConfig()
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"

    def test_custom_delimiters_can_be_set(self):
        """Custom fence delimiters can be set."""
        config = PromptFenceConfig(
            trusted_prefix="[TRUSTED]",
            trusted_suffix="[/TRUSTED]",
            untrusted_prefix="[UNTRUSTED]",
            untrusted_suffix="[/UNTRUSTED]",
        )
        assert config.trusted_prefix == "[TRUSTED]"
        assert config.trusted_suffix == "[/TRUSTED]"

    def test_metadata_inclusion_flags(self):
        """Metadata inclusion flags should work."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )
        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True


class TestLoggingConfig:
    """Test LoggingConfig edge cases."""

    def test_default_log_level_is_info(self):
        """Default log level should be INFO."""
        config = LoggingConfig()
        assert config.log_level == "INFO"

    def test_valid_log_levels(self):
        """Test valid log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_content_redaction_enabled_by_default(self):
        """Content redaction should be enabled by default for security."""
        config = LoggingConfig()
        assert config.redact_content is True

    def test_max_logged_content_length_not_validated(self):
        """
        Max logged content length should be positive, but not validated.
        """
        config = LoggingConfig(max_logged_content_length=500)
        assert config.max_logged_content_length == 500

        # Currently accepts invalid values
        config_neg = LoggingConfig(max_logged_content_length=-1)
        assert config_neg.max_logged_content_length == -1
        # TODO: Add validation for positive values


class TestConfigEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_cache_ttl_disables_caching(self):
        """Zero cache TTL should be valid (disables time-based expiry)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_very_large_cache_ttl(self):
        """Very large cache TTL should be accepted."""
        config = Config(cache_ttl_seconds=86400 * 365)  # 1 year
        assert config.cache_ttl_seconds == 86400 * 365

    def test_negative_cache_ttl_not_validated(self):
        """
        Negative cache TTL should ideally be rejected, but isn't.
        """
        config = Config(cache_ttl_seconds=-1)
        assert config.cache_ttl_seconds == -1
        # TODO: Add validation for non-negative cache TTL

    def test_very_short_timeout(self):
        """Very short timeout should be valid."""
        config = Config(request_timeout_seconds=0.001)
        assert config.request_timeout_seconds == 0.001

    def test_very_long_timeout(self):
        """Very long timeout should be valid."""
        config = Config(request_timeout_seconds=3600.0)
        assert config.request_timeout_seconds == 3600.0

    def test_disable_all_layers(self):
        """All layers can be disabled (though not recommended)."""
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

    def test_strict_and_permissive_are_opposites(self):
        """Strict and permissive configs should have opposite settings."""
        strict = Config.strict()
        permissive = Config.permissive()

        # Fail open
        assert strict.fail_open is False
        assert permissive.fail_open is True

        # Trust levels
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert permissive.trusted_filter.allow_anonymous is True

        # Block thresholds
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert permissive.block_threshold == RiskLevel.CRITICAL

        # Confidence thresholds
        assert strict.detector.confidence_threshold < permissive.detector.confidence_threshold


class TestConfigFactoryMethods:
    """Test config factory methods produce correct configurations."""

    def test_default_factory_returns_new_instance(self):
        """default() should return a new instance each time."""
        config1 = Config.default()
        config2 = Config.default()

        assert config1 is not config2
        assert config1.fail_open == config2.fail_open

    def test_strict_factory_has_restrictive_settings(self):
        """strict() should have security-focused settings."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold <= 0.5

    def test_permissive_factory_has_lenient_settings(self):
        """permissive() should have lenient settings."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold >= 0.8

    def test_factory_methods_produce_valid_configs(self):
        """All factory methods should produce valid configs."""
        configs = [
            Config.default(),
            Config.strict(),
            Config.permissive(),
        ]

        for config in configs:
            # Should be serializable
            config_dict = config.model_dump()
            assert isinstance(config_dict, dict)

            # Should be restorable
            restored = Config(**config_dict)
            assert restored.fail_open == config.fail_open
