"""
Unit tests for configuration validation.

Tests edge cases, validation logic, and configuration presets to ensure
robust configuration handling and early detection of invalid settings.
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

    def test_default_config_creation(self):
        """Default config should be created successfully."""
        config = Config.default()
        assert config is not None
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_default_fail_open_is_false(self):
        """Default config should fail closed for security."""
        config = Config.default()
        assert config.fail_open is False

    def test_default_strict_mode_is_false(self):
        """Default config should not be in strict mode."""
        config = Config.default()
        assert config.strict_mode is False

    def test_default_trusted_filter_allows_external(self):
        """Default trusted filter should allow external contributors."""
        config = Config.default()
        assert config.trusted_filter.allow_external is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL


class TestConfigPresets:
    """Tests for preset configurations (strict, permissive)."""

    def test_strict_config_has_higher_security(self):
        """Strict config should have stricter security settings."""
        strict = Config.strict()
        default = Config.default()

        # Stricter trust requirements - DEVELOPER is stricter than EXTERNAL
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert default.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL
        assert strict.trusted_filter.allow_anonymous is False
        assert strict.trusted_filter.allow_external is False

        # Lower confidence threshold (catches more)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Block threshold should be stricter (MEDIUM blocks more than HIGH)
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert default.block_threshold == RiskLevel.HIGH

    def test_permissive_config_reduces_false_positives(self):
        """Permissive config should reduce false positives."""
        permissive = Config.permissive()
        default = Config.default()

        # More lenient trust
        assert permissive.trusted_filter.allow_anonymous is True
        assert permissive.trusted_filter.allow_external is True

        # Higher confidence threshold (requires more certainty)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Fail open on errors
        assert permissive.fail_open is True

        # Only block critical threats
        assert permissive.block_threshold == RiskLevel.CRITICAL

    def test_strict_mode_consistent(self):
        """Strict config should have consistent strict settings."""
        config = Config.strict()
        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.data_filter.aggressiveness == "aggressive"

    def test_permissive_mode_consistent(self):
        """Permissive config should have consistent permissive settings."""
        config = Config.permissive()
        assert config.fail_open is True
        assert config.data_filter.aggressiveness == "minimal"


class TestDetectorConfigValidation:
    """Tests for detector configuration validation."""

    def test_confidence_threshold_valid_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid values
        DetectorConfig(confidence_threshold=0.0)
        DetectorConfig(confidence_threshold=0.5)
        DetectorConfig(confidence_threshold=1.0)

    def test_confidence_threshold_below_zero_accepted(self):
        """Confidence threshold below 0 is currently accepted (no validation)."""
        # NOTE: This documents current behavior - should add validation in future
        config = DetectorConfig(confidence_threshold=-0.1)
        assert config.confidence_threshold == -0.1

    def test_confidence_threshold_above_one_accepted(self):
        """Confidence threshold above 1 is currently accepted (no validation)."""
        # NOTE: This documents current behavior - should add validation in future
        config = DetectorConfig(confidence_threshold=1.5)
        assert config.confidence_threshold == 1.5

    def test_pattern_confidence_boost_valid(self):
        """Pattern confidence boost should be positive."""
        config = DetectorConfig(pattern_confidence_boost=0.2)
        assert config.pattern_confidence_boost == 0.2

    def test_tool_output_sensitivity_valid(self):
        """Tool output sensitivity should be positive."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

    def test_ml_batch_size_positive(self):
        """ML batch size must be positive."""
        config = DetectorConfig(ml_batch_size=16)
        assert config.ml_batch_size == 16

    def test_ml_max_length_positive(self):
        """ML max length must be positive."""
        config = DetectorConfig(ml_max_length=256)
        assert config.ml_max_length == 256

    def test_custom_patterns_empty_by_default(self):
        """Custom patterns should be empty by default."""
        config = DetectorConfig()
        assert config.custom_patterns == {}

    def test_custom_patterns_can_be_added(self):
        """Custom patterns should be addable."""
        config = DetectorConfig(
            custom_patterns={"test_pattern": r"test\s+regex"}
        )
        assert "test_pattern" in config.custom_patterns


class TestDataFilterConfigValidation:
    """Tests for data filter configuration validation."""

    def test_valid_sanitization_modes(self):
        """Valid sanitization modes should be accepted."""
        valid_modes = ["remove", "mask", "escape", "tag"]
        for mode in valid_modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness_levels(self):
        """Valid aggressiveness levels should be accepted."""
        valid_levels = ["minimal", "balanced", "aggressive"]
        for level in valid_levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_positive(self):
        """Max content length must be positive."""
        config = DataFilterConfig(max_content_length=50000)
        assert config.max_content_length == 50000

    def test_custom_removal_patterns_empty_by_default(self):
        """Custom removal patterns should be empty by default."""
        config = DataFilterConfig()
        assert config.custom_removal_patterns == []

    def test_custom_removal_patterns_can_be_added(self):
        """Custom removal patterns should be addable."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"pattern1", r"pattern2"]
        )
        assert len(config.custom_removal_patterns) == 2


class TestTrustedFilterConfigValidation:
    """Tests for trusted filter configuration validation."""

    def test_trust_level_enum_validation(self):
        """Trust levels should be valid TrustLevel enum values."""
        for trust_level in TrustLevel:
            config = TrustedFilterConfig(minimum_trust_level=trust_level)
            assert config.minimum_trust_level == trust_level

    def test_allowed_users_empty_by_default(self):
        """Allowed users should be empty by default."""
        config = TrustedFilterConfig()
        assert config.allowed_users == []

    def test_blocked_users_empty_by_default(self):
        """Blocked users should be empty by default."""
        config = TrustedFilterConfig()
        assert config.blocked_users == []

    def test_allowed_domains_empty_by_default(self):
        """Allowed domains should be empty by default."""
        config = TrustedFilterConfig()
        assert config.allowed_domains == []

    def test_blocked_domains_empty_by_default(self):
        """Blocked domains should be empty by default."""
        config = TrustedFilterConfig()
        assert config.blocked_domains == []

    def test_user_allowlist_can_be_populated(self):
        """User allowlist should be populatable."""
        users = ["user1", "user2", "user3"]
        config = TrustedFilterConfig(allowed_users=users)
        assert config.allowed_users == users

    def test_user_blocklist_can_be_populated(self):
        """User blocklist should be populatable."""
        users = ["baduser1", "baduser2"]
        config = TrustedFilterConfig(blocked_users=users)
        assert config.blocked_users == users

    def test_domain_allowlist_can_be_populated(self):
        """Domain allowlist should be populatable."""
        domains = ["trusted.com", "internal.org"]
        config = TrustedFilterConfig(allowed_domains=domains)
        assert config.allowed_domains == domains

    def test_conflicting_allow_settings(self):
        """Test behavior when both allow_anonymous and allow_external are false."""
        config = TrustedFilterConfig(
            allow_anonymous=False,
            allow_external=False,
        )
        # Should be valid but restrictive
        assert config.allow_anonymous is False
        assert config.allow_external is False


class TestPromptFenceConfigValidation:
    """Tests for prompt fence configuration validation."""

    def test_valid_fence_formats(self):
        """Valid fence formats should be accepted."""
        valid_formats = ["xml", "markdown", "json", "delimiter"]
        for fmt in valid_formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_signature_algorithm_default(self):
        """Signature algorithm should default to hmac-sha256."""
        config = PromptFenceConfig()
        assert config.signature_algorithm == "hmac-sha256"

    def test_delimiters_not_empty(self):
        """Fence delimiters should not be empty strings."""
        config = PromptFenceConfig()
        assert len(config.trusted_prefix) > 0
        assert len(config.trusted_suffix) > 0
        assert len(config.untrusted_prefix) > 0
        assert len(config.untrusted_suffix) > 0

    def test_custom_delimiters(self):
        """Custom delimiters should be settable."""
        config = PromptFenceConfig(
            trusted_prefix="<TRUSTED>",
            trusted_suffix="</TRUSTED>",
        )
        assert config.trusted_prefix == "<TRUSTED>"
        assert config.trusted_suffix == "</TRUSTED>"


class TestLoggingConfigValidation:
    """Tests for logging configuration validation."""

    def test_valid_log_levels(self):
        """Valid log levels should be accepted."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_max_logged_content_length_positive(self):
        """Max logged content length must be positive."""
        config = LoggingConfig(max_logged_content_length=500)
        assert config.max_logged_content_length == 500

    def test_redact_content_enabled_by_default(self):
        """Content redaction should be enabled by default for security."""
        config = LoggingConfig()
        assert config.redact_content is True


class TestGlobalConfigValidation:
    """Tests for global configuration settings."""

    def test_cache_ttl_positive(self):
        """Cache TTL must be positive."""
        config = Config(cache_ttl_seconds=7200)
        assert config.cache_ttl_seconds == 7200

    def test_max_concurrent_requests_positive(self):
        """Max concurrent requests must be positive."""
        config = Config(max_concurrent_requests=50)
        assert config.max_concurrent_requests == 50

    def test_request_timeout_positive(self):
        """Request timeout must be positive."""
        config = Config(request_timeout_seconds=60.0)
        assert config.request_timeout_seconds == 60.0

    def test_block_threshold_enum_validation(self):
        """Block threshold should be valid RiskLevel enum."""
        for risk_level in RiskLevel:
            config = Config(block_threshold=risk_level)
            assert config.block_threshold == risk_level

    def test_warn_threshold_enum_validation(self):
        """Warn threshold should be valid RiskLevel enum."""
        for risk_level in RiskLevel:
            config = Config(warn_threshold=risk_level)
            assert config.warn_threshold == risk_level

    def test_threshold_ordering_strict_config(self):
        """Strict config should have warn threshold <= block threshold."""
        config = Config.strict()
        # In strict mode, we warn and block more aggressively
        assert config.warn_threshold <= config.block_threshold


class TestConfigEdgeCases:
    """Tests for configuration edge cases and boundary conditions."""

    def test_empty_config_uses_defaults(self):
        """Config without parameters should use all defaults."""
        config = Config()
        default = Config.default()

        assert config.fail_open == default.fail_open
        assert config.strict_mode == default.strict_mode
        assert config.enable_caching == default.enable_caching

    def test_zero_confidence_threshold(self):
        """Zero confidence threshold should detect everything."""
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

    def test_max_confidence_threshold(self):
        """Max confidence threshold should require perfect certainty."""
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

    def test_very_large_content_length(self):
        """Very large content length should be valid."""
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_very_small_timeout(self):
        """Very small timeout should be valid."""
        config = Config(request_timeout_seconds=0.1)
        assert config.request_timeout_seconds == 0.1

    def test_disable_all_detector_components(self):
        """Detector with all components disabled should be valid but ineffective."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )
        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_disable_all_layers(self):
        """Config with all layers disabled should be valid."""
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

    def test_unicode_in_custom_patterns(self):
        """Unicode characters in custom patterns should be valid."""
        config = DetectorConfig(
            custom_patterns={"unicode_test": r"café|naïve|🔒"}
        )
        assert "unicode_test" in config.custom_patterns

    def test_special_regex_chars_in_patterns(self):
        """Special regex characters should be handled."""
        config = DetectorConfig(
            custom_patterns={"special": r"\$\{\w+\}"}  # Match ${variable}
        )
        assert "special" in config.custom_patterns


class TestConfigSerialization:
    """Tests for configuration serialization/deserialization."""

    def test_config_to_dict(self):
        """Config should be serializable to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Config should be creatable from dict."""
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

    def test_config_round_trip(self):
        """Config should survive round-trip serialization."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold
        assert restored.trusted_filter.allow_external == original.trusted_filter.allow_external
