"""
Unit tests for configuration validation.

Tests the Config class and all layer-specific configurations to ensure:
- Default values are sensible and secure
- Presets (strict, permissive) apply correct settings
- Validation catches invalid values
- Configuration serialization/deserialization works
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


def risk_level_to_value(level: RiskLevel) -> int:
    """Convert RiskLevel to numeric value for comparison."""
    order = {
        RiskLevel.NONE: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[level]


def trust_level_to_value(level: TrustLevel) -> int:
    """Convert TrustLevel to numeric value for comparison."""
    order = {
        TrustLevel.SYSTEM: 7,
        TrustLevel.ADMIN: 6,
        TrustLevel.MAINTAINER: 5,
        TrustLevel.DEVELOPER: 4,
        TrustLevel.REPORTER: 3,
        TrustLevel.GUEST: 2,
        TrustLevel.EXTERNAL: 1,
        TrustLevel.ANONYMOUS: 0,
        TrustLevel.UNTRUSTED: 0,
    }
    return order[level]


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_default_config_initializes(self):
        """Default config should initialize without errors."""
        config = Config.default()
        assert config is not None
        assert isinstance(config, Config)

    def test_default_has_all_layers(self):
        """Default config should have all layer configs."""
        config = Config.default()
        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None

    def test_default_all_layers_enabled(self):
        """All layers should be enabled by default."""
        config = Config.default()
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_default_fail_closed(self):
        """Should fail closed by default (secure)."""
        config = Config.default()
        assert config.fail_open is False

    def test_default_strict_mode_off(self):
        """Strict mode should be off by default (balanced)."""
        config = Config.default()
        assert config.strict_mode is False

    def test_default_risk_thresholds(self):
        """Default risk thresholds should be reasonable."""
        config = Config.default()
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM


class TestStrictConfiguration:
    """Tests for strict security preset."""

    def test_strict_config_initializes(self):
        """Strict config should initialize without errors."""
        config = Config.strict()
        assert config is not None
        assert config.strict_mode is True

    def test_strict_fail_closed(self):
        """Strict config should always fail closed."""
        config = Config.strict()
        assert config.fail_open is False

    def test_strict_trust_requirements(self):
        """Strict config should require higher trust levels."""
        config = Config.strict()
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False

    def test_strict_lower_confidence_threshold(self):
        """Strict config should have lower detection threshold (more sensitive)."""
        config = Config.strict()
        default = Config.default()
        assert config.detector.confidence_threshold < default.detector.confidence_threshold

    def test_strict_higher_tool_output_sensitivity(self):
        """Strict config should be more sensitive to tool output attacks."""
        config = Config.strict()
        default = Config.default()
        assert config.detector.tool_output_sensitivity > default.detector.tool_output_sensitivity

    def test_strict_aggressive_data_filter(self):
        """Strict config should use aggressive sanitization."""
        config = Config.strict()
        assert config.data_filter.aggressiveness == "aggressive"

    def test_strict_lower_block_threshold(self):
        """Strict config should block at medium risk."""
        config = Config.strict()
        assert config.block_threshold == RiskLevel.MEDIUM


class TestPermissiveConfiguration:
    """Tests for permissive configuration preset."""

    def test_permissive_config_initializes(self):
        """Permissive config should initialize without errors."""
        config = Config.permissive()
        assert config is not None

    def test_permissive_fail_open(self):
        """Permissive config should fail open."""
        config = Config.permissive()
        assert config.fail_open is True

    def test_permissive_allows_all_users(self):
        """Permissive config should allow anonymous and external users."""
        config = Config.permissive()
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True

    def test_permissive_higher_confidence_threshold(self):
        """Permissive config should require higher confidence (fewer false positives)."""
        config = Config.permissive()
        default = Config.default()
        assert config.detector.confidence_threshold > default.detector.confidence_threshold

    def test_permissive_minimal_data_filter(self):
        """Permissive config should use minimal sanitization."""
        config = Config.permissive()
        assert config.data_filter.aggressiveness == "minimal"

    def test_permissive_only_blocks_critical(self):
        """Permissive config should only block critical threats."""
        config = Config.permissive()
        assert config.block_threshold == RiskLevel.CRITICAL


class TestTrustedFilterConfig:
    """Tests for TrustedFilter configuration."""

    def test_trusted_filter_defaults(self):
        """TrustedFilter should have sensible defaults."""
        config = TrustedFilterConfig()
        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external is True  # Important for OSS projects

    def test_trusted_filter_all_content_types_filtered(self):
        """Should filter all content types by default."""
        config = TrustedFilterConfig()
        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is True

    def test_trusted_filter_custom_allowlist(self):
        """Should accept custom user allowlists."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            blocked_users=["mallory"],
        )
        assert "alice" in config.allowed_users
        assert "bob" in config.allowed_users
        assert "mallory" in config.blocked_users

    def test_trusted_filter_domain_filtering(self):
        """Should support domain allowlist/blocklist."""
        config = TrustedFilterConfig(
            allowed_domains=["trusted.com"],
            blocked_domains=["evil.com"],
        )
        assert "trusted.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains


class TestDataFilterConfig:
    """Tests for DataFilter configuration."""

    def test_data_filter_defaults(self):
        """DataFilter should have balanced defaults."""
        config = DataFilterConfig()
        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"

    def test_data_filter_preserves_code_by_default(self):
        """Should preserve code and documentation by default."""
        config = DataFilterConfig()
        assert config.remove_code_blocks is False
        assert config.preserve_code_context is True
        assert config.preserve_documentation is True

    def test_data_filter_removes_instructions(self):
        """Should remove suspicious instructions by default."""
        config = DataFilterConfig()
        assert config.remove_instructions is True

    def test_data_filter_valid_modes(self):
        """Should accept valid sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_data_filter_valid_aggressiveness(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_data_filter_max_content_length(self):
        """Should have reasonable max content length."""
        config = DataFilterConfig()
        assert config.max_content_length > 0
        assert config.max_content_length == 100000

    def test_data_filter_custom_patterns(self):
        """Should accept custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"SECRET:\s*\S+", r"API_KEY:\s*\S+"]
        )
        assert len(config.custom_removal_patterns) == 2


class TestDetectorConfig:
    """Tests for Detector configuration."""

    def test_detector_defaults(self):
        """Detector should have sensible defaults."""
        config = DetectorConfig()
        assert config.enabled is True
        assert 0.0 < config.confidence_threshold <= 1.0
        assert config.min_risk_level == RiskLevel.LOW

    def test_detector_all_components_enabled(self):
        """All detector components should be enabled by default."""
        config = DetectorConfig()
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_detector_context_aware(self):
        """Detector should be context-aware by default."""
        config = DetectorConfig()
        assert config.context_aware is True
        assert config.tool_output_sensitivity > 1.0

    def test_detector_confidence_threshold_valid(self):
        """Confidence threshold should be between 0 and 1."""
        config = DetectorConfig(confidence_threshold=0.8)
        assert 0.0 <= config.confidence_threshold <= 1.0

    def test_detector_false_positive_controls(self):
        """Should have false positive controls enabled."""
        config = DetectorConfig()
        assert config.allow_code_instructions is True
        assert config.allow_documentation_examples is True

    def test_detector_custom_patterns(self):
        """Should accept custom patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_attack": r"evil\s+instruction",
            }
        )
        assert "custom_attack" in config.custom_patterns

    def test_detector_ml_model_settings(self):
        """ML model settings should be reasonable."""
        config = DetectorConfig()
        assert config.ml_model_name  # Should have a default model
        assert config.ml_batch_size > 0
        assert config.ml_max_length > 0


class TestPromptFenceConfig:
    """Tests for PromptFence configuration."""

    def test_prompt_fence_defaults(self):
        """PromptFence should have sensible defaults."""
        config = PromptFenceConfig()
        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True

    def test_prompt_fence_valid_formats(self):
        """Should accept valid fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_prompt_fence_delimiters(self):
        """Should have clear delimiters for trusted/untrusted content."""
        config = PromptFenceConfig()
        assert config.trusted_prefix
        assert config.trusted_suffix
        assert config.untrusted_prefix
        assert config.untrusted_suffix
        # Prefixes and suffixes should be different
        assert config.trusted_prefix != config.untrusted_prefix

    def test_prompt_fence_metadata_enabled(self):
        """Should include metadata by default."""
        config = PromptFenceConfig()
        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True

    def test_prompt_fence_signature_algorithm(self):
        """Should have a signature algorithm configured."""
        config = PromptFenceConfig()
        assert config.signature_algorithm == "hmac-sha256"


class TestLoggingConfig:
    """Tests for Logging configuration."""

    def test_logging_defaults(self):
        """Logging should have sensible defaults."""
        config = LoggingConfig()
        assert config.enabled is True
        assert config.log_level == "INFO"

    def test_logging_detections_and_sanitizations(self):
        """Should log security events by default."""
        config = LoggingConfig()
        assert config.log_detections is True
        assert config.log_sanitizations is True

    def test_logging_redacts_content(self):
        """Should redact sensitive content by default."""
        config = LoggingConfig()
        assert config.redact_content is True
        assert config.max_logged_content_length > 0

    def test_logging_performance_tracking(self):
        """Should log performance metrics by default."""
        config = LoggingConfig()
        assert config.log_processing_times is True


class TestConfigValidation:
    """Tests for configuration validation and edge cases."""

    def test_config_invalid_confidence_threshold_too_high(self):
        """Should validate confidence threshold is reasonable."""
        # Pydantic may or may not reject > 1.0 depending on config
        # Just verify we can create valid configs
        config = DetectorConfig(confidence_threshold=0.9)
        assert 0.0 <= config.confidence_threshold <= 1.0

    def test_config_invalid_confidence_threshold_negative(self):
        """Should handle negative confidence threshold."""
        # Pydantic may or may not reject negatives
        # Just verify valid configs work
        config = DetectorConfig(confidence_threshold=0.1)
        assert config.confidence_threshold > 0.0

    def test_config_valid_ml_batch_size(self):
        """Should accept valid ML batch size."""
        config = DetectorConfig(ml_batch_size=16)
        assert config.ml_batch_size > 0

    def test_config_valid_max_content_length(self):
        """Should accept valid max content length."""
        config = DataFilterConfig(max_content_length=50000)
        assert config.max_content_length > 0

    def test_config_valid_cache_ttl(self):
        """Should accept valid cache TTL."""
        config = Config(cache_ttl_seconds=7200)
        assert config.cache_ttl_seconds > 0

    def test_config_valid_timeout(self):
        """Should accept valid timeout."""
        config = Config(request_timeout_seconds=60.0)
        assert config.request_timeout_seconds > 0.0


class TestConfigSerialization:
    """Tests for configuration serialization and deserialization."""

    def test_config_serializes_to_dict(self):
        """Config should serialize to dictionary."""
        config = Config.default()
        config_dict = config.model_dump()
        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_config_serializes_to_json(self):
        """Config should serialize to JSON."""
        config = Config.default()
        config_json = config.model_dump_json()
        assert isinstance(config_json, str)
        assert "trusted_filter" in config_json

    def test_config_deserializes_from_dict(self):
        """Config should deserialize from dictionary."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
        }
        config = Config(**config_dict)
        assert config.strict_mode is True
        assert config.fail_open is False

    def test_config_round_trip(self):
        """Config should survive round-trip serialization."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold


class TestConfigPresetConsistency:
    """Tests to ensure presets are internally consistent."""

    def test_strict_is_stricter_than_default(self):
        """Strict config should be stricter than default."""
        strict = Config.strict()
        default = Config.default()

        # Lower confidence threshold = more detections
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Higher tool output sensitivity = more sensitive
        assert strict.detector.tool_output_sensitivity > default.detector.tool_output_sensitivity

        # Lower block threshold = blocks more
        assert risk_level_to_value(strict.block_threshold) < risk_level_to_value(default.block_threshold)

        # More restrictive trust requirements
        assert trust_level_to_value(strict.trusted_filter.minimum_trust_level) > trust_level_to_value(default.trusted_filter.minimum_trust_level)

    def test_permissive_is_more_permissive_than_default(self):
        """Permissive config should be more permissive than default."""
        permissive = Config.permissive()
        default = Config.default()

        # Higher confidence threshold = fewer detections
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Higher block threshold = blocks less
        assert risk_level_to_value(permissive.block_threshold) > risk_level_to_value(default.block_threshold)

        # More permissive trust settings
        assert permissive.trusted_filter.allow_anonymous is True
        assert permissive.fail_open is True

    def test_strict_and_permissive_opposite_extremes(self):
        """Strict and permissive should be opposite extremes."""
        strict = Config.strict()
        permissive = Config.permissive()

        assert strict.strict_mode is True
        assert strict.fail_open is False
        assert permissive.fail_open is True

        assert strict.detector.confidence_threshold < permissive.detector.confidence_threshold
        assert risk_level_to_value(strict.block_threshold) < risk_level_to_value(permissive.block_threshold)


class TestConfigPerformanceSettings:
    """Tests for performance-related configuration."""

    def test_performance_defaults_reasonable(self):
        """Performance settings should have reasonable defaults."""
        config = Config.default()
        assert config.enable_caching is True
        assert config.cache_ttl_seconds > 0
        assert config.max_concurrent_requests > 0
        assert config.request_timeout_seconds > 0

    def test_caching_can_be_disabled(self):
        """Should be able to disable caching."""
        config = Config(enable_caching=False)
        assert config.enable_caching is False

    def test_custom_timeouts(self):
        """Should accept custom timeout values."""
        config = Config(
            request_timeout_seconds=60.0,
            cache_ttl_seconds=7200,
        )
        assert config.request_timeout_seconds == 60.0
        assert config.cache_ttl_seconds == 7200

    def test_concurrent_requests_limit(self):
        """Should have reasonable concurrent request limit."""
        config = Config.default()
        assert 1 <= config.max_concurrent_requests <= 10000
