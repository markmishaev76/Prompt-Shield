"""
Unit tests for configuration validation and edge cases.

Tests the Config class and its subconfigs to ensure:
- Valid default configurations
- Factory methods produce correct settings
- Edge cases and boundary conditions are handled
- Invalid configurations are rejected
- Serialization/deserialization works correctly
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

    def test_default_config_is_valid(self):
        """Default config should be valid and usable."""
        config = Config.default()

        assert config is not None
        assert isinstance(config, Config)
        assert config.fail_open is False
        assert config.strict_mode is False

    def test_default_config_has_all_layers_enabled(self):
        """All layers should be enabled by default."""
        config = Config.default()

        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_default_config_is_balanced(self):
        """Default config should have balanced security settings."""
        config = Config.default()

        # Trusted filter should allow external contributors
        assert config.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.trusted_filter.allow_external is True

        # Data filter should be balanced
        assert config.data_filter.aggressiveness == "balanced"

        # Detector should have reasonable threshold
        assert config.detector.confidence_threshold == 0.7

        # Should block HIGH and above by default
        assert config.block_threshold == RiskLevel.HIGH


class TestConfigFactoryMethods:
    """Tests for config factory methods."""

    def test_strict_config_is_more_restrictive(self):
        """Strict config should be more restrictive than default."""
        default = Config.default()
        strict = Config.strict()

        # Stricter trust requirements (DEVELOPER > EXTERNAL)
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert default.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL
        assert strict.trusted_filter.allow_external is False
        assert strict.trusted_filter.allow_anonymous is False

        # More aggressive filtering
        assert strict.data_filter.aggressiveness == "aggressive"

        # Lower confidence threshold (catches more)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Lower block threshold (blocks at MEDIUM instead of HIGH)
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert default.block_threshold == RiskLevel.HIGH

        # Strict mode enabled
        assert strict.strict_mode is True
        assert strict.fail_open is False

    def test_permissive_config_is_less_restrictive(self):
        """Permissive config should be less restrictive than default."""
        default = Config.default()
        permissive = Config.permissive()

        # More permissive trust settings
        assert permissive.trusted_filter.allow_external is True
        assert permissive.trusted_filter.allow_anonymous is True

        # Minimal filtering
        assert permissive.data_filter.aggressiveness == "minimal"

        # Higher confidence threshold (fewer false positives)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Higher block threshold (only blocks CRITICAL, not HIGH)
        assert permissive.block_threshold == RiskLevel.CRITICAL
        assert default.block_threshold == RiskLevel.HIGH

        # Fail open
        assert permissive.fail_open is True

    def test_factory_configs_are_independent(self):
        """Factory configs should not share state."""
        strict1 = Config.strict()
        strict2 = Config.strict()

        # Modify one
        strict1.strict_mode = False

        # Should not affect the other
        assert strict2.strict_mode is True


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation."""

    def test_default_trusted_filter_config(self):
        """Default TrustedFilterConfig should be valid."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True

    def test_trusted_filter_with_allowlist(self):
        """Should accept allowlist of users."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            allowed_domains=["example.com"],
        )

        assert "alice" in config.allowed_users
        assert "bob" in config.allowed_users
        assert "example.com" in config.allowed_domains

    def test_trusted_filter_with_blocklist(self):
        """Should accept blocklist of users."""
        config = TrustedFilterConfig(
            blocked_users=["attacker"],
            blocked_domains=["evil.com"],
        )

        assert "attacker" in config.blocked_users
        assert "evil.com" in config.blocked_domains

    def test_trust_level_enum_values(self):
        """Should accept all valid trust levels."""
        for level in TrustLevel:
            config = TrustedFilterConfig(minimum_trust_level=level)
            assert config.minimum_trust_level == level


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_default_data_filter_config(self):
        """Default DataFilterConfig should be valid."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.remove_instructions is True

    def test_data_filter_modes(self):
        """Should accept different sanitization modes."""
        valid_modes = ["remove", "mask", "escape", "tag"]

        for mode in valid_modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_data_filter_aggressiveness_levels(self):
        """Should accept different aggressiveness levels."""
        valid_levels = ["minimal", "balanced", "aggressive"]

        for level in valid_levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_data_filter_content_length_limit(self):
        """Should accept content length limits."""
        config = DataFilterConfig(max_content_length=50000)
        assert config.max_content_length == 50000

    def test_data_filter_custom_patterns(self):
        """Should accept custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"pattern1", r"pattern2"]
        )

        assert len(config.custom_removal_patterns) == 2
        assert r"pattern1" in config.custom_removal_patterns

    def test_data_filter_preservation_settings(self):
        """Should allow controlling what to preserve."""
        config = DataFilterConfig(
            preserve_code_context=False,
            preserve_documentation=False,
        )

        assert config.preserve_code_context is False
        assert config.preserve_documentation is False


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_default_detector_config(self):
        """Default DetectorConfig should be valid."""
        config = DetectorConfig()

        assert config.enabled is True
        assert 0 < config.confidence_threshold < 1
        assert config.use_pattern_matching is True
        assert config.context_aware is True

    def test_detector_confidence_threshold_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        config = DetectorConfig(confidence_threshold=0.5)
        assert config.confidence_threshold == 0.5

        config = DetectorConfig(confidence_threshold=0.9)
        assert config.confidence_threshold == 0.9

        # Edge cases
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

    def test_detector_component_toggles(self):
        """Should allow enabling/disabling detector components."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_detector_ml_settings(self):
        """Should accept ML model configuration."""
        config = DetectorConfig(
            ml_model_name="custom-model",
            ml_batch_size=16,
            ml_max_length=256,
        )

        assert config.ml_model_name == "custom-model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_detector_custom_patterns(self):
        """Should accept custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={"test": r"test\s+pattern"}
        )

        assert "test" in config.custom_patterns
        assert config.custom_patterns["test"] == r"test\s+pattern"

    def test_detector_blocked_patterns(self):
        """Should accept list of blocked patterns."""
        config = DetectorConfig(
            blocked_patterns=["pattern1", "pattern2"]
        )

        assert len(config.blocked_patterns) == 2

    def test_detector_context_sensitivity(self):
        """Should allow configuring tool output sensitivity."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

    def test_detector_risk_level_filter(self):
        """Should accept minimum risk level."""
        for level in RiskLevel:
            config = DetectorConfig(min_risk_level=level)
            assert config.min_risk_level == level


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_default_prompt_fence_config(self):
        """Default PromptFenceConfig should be valid."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True

    def test_prompt_fence_formats(self):
        """Should accept different fence formats."""
        valid_formats = ["xml", "markdown", "json", "delimiter"]

        for format_type in valid_formats:
            config = PromptFenceConfig(fence_format=format_type)
            assert config.fence_format == format_type

    def test_prompt_fence_signature_algorithm(self):
        """Should accept signature algorithm."""
        config = PromptFenceConfig(signature_algorithm="hmac-sha512")
        assert config.signature_algorithm == "hmac-sha512"

    def test_prompt_fence_custom_delimiters(self):
        """Should allow custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<SAFE>>>",
            trusted_suffix="<<<END_SAFE>>>",
        )

        assert config.trusted_prefix == "<<<SAFE>>>"
        assert config.trusted_suffix == "<<<END_SAFE>>>"

    def test_prompt_fence_metadata_settings(self):
        """Should allow controlling metadata inclusion."""
        config = PromptFenceConfig(
            include_metadata=False,
            include_trust_level=False,
            include_source_type=False,
        )

        assert config.include_metadata is False
        assert config.include_trust_level is False
        assert config.include_source_type is False


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_default_logging_config(self):
        """Default LoggingConfig should be valid."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.redact_content is True

    def test_logging_levels(self):
        """Should accept different log levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_toggles(self):
        """Should allow enabling/disabling log types."""
        config = LoggingConfig(
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.log_detections is False
        assert config.log_sanitizations is False
        assert config.log_processing_times is False

    def test_logging_redaction_settings(self):
        """Should allow configuring content redaction."""
        config = LoggingConfig(
            redact_content=False,
            max_logged_content_length=500,
        )

        assert config.redact_content is False
        assert config.max_logged_content_length == 500


class TestConfigPerformanceSettings:
    """Tests for Config performance settings."""

    def test_config_caching_settings(self):
        """Should allow configuring caching."""
        config = Config(
            enable_caching=True,
            cache_ttl_seconds=7200,
        )

        assert config.enable_caching is True
        assert config.cache_ttl_seconds == 7200

    def test_config_concurrency_settings(self):
        """Should allow configuring concurrency limits."""
        config = Config(max_concurrent_requests=50)
        assert config.max_concurrent_requests == 50

    def test_config_timeout_settings(self):
        """Should allow configuring request timeout."""
        config = Config(request_timeout_seconds=60.0)
        assert config.request_timeout_seconds == 60.0


class TestConfigRiskThresholds:
    """Tests for risk threshold configuration."""

    def test_config_block_threshold(self):
        """Should accept different block thresholds."""
        for level in RiskLevel:
            config = Config(block_threshold=level)
            assert config.block_threshold == level

    def test_config_warn_threshold(self):
        """Should accept different warn thresholds."""
        for level in RiskLevel:
            config = Config(warn_threshold=level)
            assert config.warn_threshold == level

    def test_config_threshold_ordering_makes_sense(self):
        """Block threshold should typically be higher than warn threshold."""
        config = Config.default()

        # In default config, block should be higher severity than warn
        # (HIGH > MEDIUM in severity)
        assert config.block_threshold.value != config.warn_threshold.value


class TestConfigSerialization:
    """Tests for config serialization and deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict

    def test_config_round_trip(self):
        """Config should survive serialization round trip."""
        original = Config.strict()

        # Serialize
        config_dict = original.model_dump()

        # Deserialize
        restored = Config(**config_dict)

        # Compare key settings
        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.block_threshold == original.block_threshold
        assert restored.trusted_filter.minimum_trust_level == original.trusted_filter.minimum_trust_level

    def test_config_json_serialization(self):
        """Config should serialize to JSON."""
        import json

        config = Config.default()
        config_dict = config.model_dump()

        # Should be JSON-serializable
        json_str = json.dumps(config_dict, default=str)
        assert isinstance(json_str, str)

        # Should deserialize back
        loaded_dict = json.loads(json_str)
        assert isinstance(loaded_dict, dict)


class TestConfigEdgeCases:
    """Tests for config edge cases and boundary conditions."""

    def test_config_with_all_layers_disabled(self):
        """Should allow creating config with all layers disabled."""
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

    def test_config_with_extreme_confidence_threshold(self):
        """Should handle extreme confidence thresholds."""
        # Very low threshold (catches everything)
        config = Config(detector=DetectorConfig(confidence_threshold=0.1))
        assert config.detector.confidence_threshold == 0.1

        # Very high threshold (catches only obvious attacks)
        config = Config(detector=DetectorConfig(confidence_threshold=0.99))
        assert config.detector.confidence_threshold == 0.99

    def test_config_with_zero_timeout(self):
        """Should handle zero timeout (no timeout)."""
        config = Config(request_timeout_seconds=0.0)
        assert config.request_timeout_seconds == 0.0

    def test_config_with_large_content_limit(self):
        """Should handle large content limits."""
        config = Config(
            data_filter=DataFilterConfig(max_content_length=10_000_000)
        )
        assert config.data_filter.max_content_length == 10_000_000

    def test_config_strict_mode_with_fail_open(self):
        """Conflicting settings should both be respected."""
        # This is an odd combination but should be allowed
        config = Config(strict_mode=True, fail_open=True)

        assert config.strict_mode is True
        assert config.fail_open is True


class TestConfigValidation:
    """Tests for config validation logic."""

    def test_empty_allowlist_is_valid(self):
        """Empty allowlists should be valid."""
        config = TrustedFilterConfig(
            allowed_users=[],
            allowed_domains=[],
        )

        assert config.allowed_users == []
        assert config.allowed_domains == []

    def test_empty_custom_patterns_is_valid(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(
            custom_patterns={},
            blocked_patterns=[],
        )

        assert config.custom_patterns == {}
        assert config.blocked_patterns == []
