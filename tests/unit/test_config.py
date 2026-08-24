"""
Unit tests for configuration validation.

Tests the Config class and its validation logic to ensure
security-critical settings are properly validated and enforced.
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
        """Should create config with defaults."""
        config = Config.default()

        assert config.trusted_filter.enabled
        assert config.data_filter.enabled
        assert config.detector.enabled
        assert config.prompt_fence.enabled
        assert config.logging.enabled

    def test_default_config_not_strict(self):
        """Default config should not be strict."""
        config = Config.default()

        assert not config.strict_mode
        assert not config.fail_open

    def test_default_allows_external_contributors(self):
        """Default should allow external contributors (OSS-friendly)."""
        config = Config.default()

        assert config.trusted_filter.allow_external
        assert config.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL


class TestStrictConfig:
    """Tests for strict security configuration."""

    def test_strict_config_creation(self):
        """Should create strict config."""
        config = Config.strict()

        assert config.strict_mode
        assert not config.fail_open

    def test_strict_blocks_external(self):
        """Strict mode should block external contributors."""
        config = Config.strict()

        assert not config.trusted_filter.allow_external
        assert not config.trusted_filter.allow_anonymous
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER

    def test_strict_aggressive_sanitization(self):
        """Strict mode should use aggressive sanitization."""
        config = Config.strict()

        assert config.data_filter.aggressiveness == "aggressive"

    def test_strict_lower_confidence_threshold(self):
        """Strict mode should have lower detection threshold."""
        config = Config.strict()

        assert config.detector.confidence_threshold < Config.default().detector.confidence_threshold
        assert config.detector.confidence_threshold == 0.5

    def test_strict_blocks_at_medium_risk(self):
        """Strict mode should block at MEDIUM risk."""
        config = Config.strict()

        assert config.block_threshold == RiskLevel.MEDIUM


class TestPermissiveConfig:
    """Tests for permissive configuration."""

    def test_permissive_config_creation(self):
        """Should create permissive config."""
        config = Config.permissive()

        assert config.fail_open
        assert not config.strict_mode

    def test_permissive_allows_all(self):
        """Permissive mode should allow anonymous and external."""
        config = Config.permissive()

        assert config.trusted_filter.allow_anonymous
        assert config.trusted_filter.allow_external

    def test_permissive_minimal_sanitization(self):
        """Permissive mode should use minimal sanitization."""
        config = Config.permissive()

        assert config.data_filter.aggressiveness == "minimal"

    def test_permissive_high_confidence_threshold(self):
        """Permissive mode should have high detection threshold."""
        config = Config.permissive()

        assert config.detector.confidence_threshold > Config.default().detector.confidence_threshold
        assert config.detector.confidence_threshold == 0.85

    def test_permissive_blocks_only_critical(self):
        """Permissive mode should block only CRITICAL risk."""
        config = Config.permissive()

        assert config.block_threshold == RiskLevel.CRITICAL


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation."""

    def test_trust_level_enum_validation(self):
        """Should accept valid trust levels."""
        config = TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)
        assert config.minimum_trust_level == TrustLevel.DEVELOPER

    def test_allowlist_blocklist(self):
        """Should handle allowlists and blocklists."""
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

    def test_filter_content_type_flags(self):
        """Should control content type filtering."""
        config = TrustedFilterConfig(
            filter_issue_content=True,
            filter_comments=False,
            filter_file_content=True,
            filter_wiki_pages=False,
        )

        assert config.filter_issue_content
        assert not config.filter_comments
        assert config.filter_file_content
        assert not config.filter_wiki_pages


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_valid_modes(self):
        """Should accept valid sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_validation(self):
        """Should have reasonable max content length."""
        config = DataFilterConfig(max_content_length=50000)
        assert config.max_content_length == 50000

    def test_custom_removal_patterns(self):
        """Should accept custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"ADMIN:", r"SECRET:"]
        )

        assert len(config.custom_removal_patterns) == 2

    def test_preservation_flags(self):
        """Should control content preservation."""
        config = DataFilterConfig(
            preserve_code_context=True,
            preserve_documentation=False,
        )

        assert config.preserve_code_context
        assert not config.preserve_documentation


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_confidence_threshold_range(self):
        """Confidence threshold should be between 0 and 1."""
        config = DetectorConfig(confidence_threshold=0.75)
        assert 0 <= config.confidence_threshold <= 1

    def test_confidence_threshold_boundary_values(self):
        """Should accept boundary values for confidence."""
        config_zero = DetectorConfig(confidence_threshold=0.0)
        config_one = DetectorConfig(confidence_threshold=1.0)

        assert config_zero.confidence_threshold == 0.0
        assert config_one.confidence_threshold == 1.0

    def test_min_risk_level_validation(self):
        """Should accept valid risk levels."""
        config = DetectorConfig(min_risk_level=RiskLevel.MEDIUM)
        assert config.min_risk_level == RiskLevel.MEDIUM

    def test_detector_component_flags(self):
        """Should control detection components."""
        config = DetectorConfig(
            use_pattern_matching=True,
            use_ml_model=False,
            use_heuristics=True,
        )

        assert config.use_pattern_matching
        assert not config.use_ml_model
        assert config.use_heuristics

    def test_tool_output_sensitivity_multiplier(self):
        """Should have tool output sensitivity multiplier."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

    def test_custom_patterns_dict(self):
        """Should accept custom pattern definitions."""
        config = DetectorConfig(
            custom_patterns={
                "test_pattern": r"dangerous\s+action",
            }
        )

        assert "test_pattern" in config.custom_patterns

    def test_context_awareness_flag(self):
        """Should have context awareness flag."""
        config = DetectorConfig(context_aware=True)
        assert config.context_aware


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_signature_algorithm(self):
        """Should have signature algorithm setting."""
        config = PromptFenceConfig(signature_algorithm="hmac-sha256")
        assert config.signature_algorithm == "hmac-sha256"

    def test_fence_delimiters(self):
        """Should have customizable fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<SAFE>>>",
            trusted_suffix="<<<END_SAFE>>>",
        )

        assert config.trusted_prefix == "<<<SAFE>>>"
        assert config.trusted_suffix == "<<<END_SAFE>>>"

    def test_metadata_flags(self):
        """Should control metadata inclusion."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=False,
        )

        assert config.include_metadata
        assert config.include_trust_level
        assert not config.include_source_type


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_log_level_setting(self):
        """Should accept valid log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_flags(self):
        """Should control what gets logged."""
        config = LoggingConfig(
            log_detections=True,
            log_sanitizations=False,
            log_processing_times=True,
        )

        assert config.log_detections
        assert not config.log_sanitizations
        assert config.log_processing_times

    def test_content_redaction(self):
        """Should have content redaction settings."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100,
        )

        assert config.redact_content
        assert config.max_logged_content_length == 100


class TestMasterConfig:
    """Tests for master Config class."""

    def test_nested_config_creation(self):
        """Should create config with nested configs."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            detector=DetectorConfig(confidence_threshold=0.9),
        )

        assert not config.trusted_filter.enabled
        assert config.detector.confidence_threshold == 0.9

    def test_risk_threshold_settings(self):
        """Should have configurable risk thresholds."""
        config = Config(
            block_threshold=RiskLevel.HIGH,
            warn_threshold=RiskLevel.LOW,
        )

        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.LOW

    def test_performance_settings(self):
        """Should have performance configuration."""
        config = Config(
            enable_caching=True,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=15.0,
        )

        assert config.enable_caching
        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 15.0

    def test_fail_open_setting(self):
        """Should have fail-open configuration."""
        config_fail_open = Config(fail_open=True)
        config_fail_closed = Config(fail_open=False)

        assert config_fail_open.fail_open
        assert not config_fail_closed.fail_open


class TestConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_allowlists(self):
        """Should handle empty allowlists."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
        )

        assert config.allowed_users == []
        assert config.blocked_users == []

    def test_zero_cache_ttl(self):
        """Should accept zero cache TTL (caching disabled)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_all_layers_disabled(self):
        """Should allow disabling all layers."""
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

    def test_very_low_confidence_threshold(self):
        """Should accept very low confidence threshold."""
        config = DetectorConfig(confidence_threshold=0.01)
        assert config.confidence_threshold == 0.01

    def test_very_high_confidence_threshold(self):
        """Should accept very high confidence threshold."""
        config = DetectorConfig(confidence_threshold=0.99)
        assert config.confidence_threshold == 0.99

    def test_large_max_content_length(self):
        """Should accept large content length limits."""
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_small_max_logged_content(self):
        """Should accept small max logged content length."""
        config = LoggingConfig(max_logged_content_length=10)
        assert config.max_logged_content_length == 10


class TestConfigSerialization:
    """Tests for config serialization/deserialization."""

    def test_config_to_dict(self):
        """Should serialize config to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Should create config from dict."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
            "detector": {
                "confidence_threshold": 0.8,
            },
        }

        config = Config(**config_dict)

        assert config.strict_mode
        assert not config.fail_open
        assert config.detector.confidence_threshold == 0.8

    def test_config_round_trip(self):
        """Should preserve config through serialization round-trip."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold
        assert restored.trusted_filter.minimum_trust_level == original.trusted_filter.minimum_trust_level


class TestConfigPresetConsistency:
    """Tests that preset configs are internally consistent."""

    def test_strict_config_is_more_restrictive(self):
        """Strict config should be more restrictive than default."""
        default = Config.default()
        strict = Config.strict()

        # Lower confidence threshold = more detections
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold
        # Higher minimum trust level = fewer allowed users
        assert strict.trusted_filter.minimum_trust_level.value > default.trusted_filter.minimum_trust_level.value
        # Lower block threshold = blocks more content
        assert strict.block_threshold.value < default.block_threshold.value

    def test_permissive_config_is_less_restrictive(self):
        """Permissive config should be less restrictive than default."""
        default = Config.default()
        permissive = Config.permissive()

        # Higher confidence threshold = fewer detections
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold
        # Higher block threshold = blocks less content
        assert permissive.block_threshold.value > default.block_threshold.value
        # Allows more users
        assert permissive.trusted_filter.allow_anonymous

    def test_all_presets_have_all_components(self):
        """All preset configs should have all components configured."""
        for preset in [Config.default(), Config.strict(), Config.permissive()]:
            assert preset.trusted_filter is not None
            assert preset.data_filter is not None
            assert preset.detector is not None
            assert preset.prompt_fence is not None
            assert preset.logging is not None
