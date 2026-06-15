"""
Unit tests for Configuration classes.

Tests configuration validation, presets, edge cases, and constraints.
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
    """Tests for TrustedFilterConfig validation and behavior."""

    def test_default_values(self):
        """Default config should have sensible values."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external is True
        assert config.allow_anonymous is False
        assert config.filter_issue_content is True

    def test_allowlist_and_blocklist(self):
        """Should handle allowlists and blocklists."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            blocked_users=["eve"],
            allowed_domains=["example.com"],
            blocked_domains=["evil.com"],
        )

        assert "alice" in config.allowed_users
        assert "eve" in config.blocked_users
        assert "example.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains

    def test_trust_level_enum_validation(self):
        """Should validate trust level enum values."""
        # Valid trust level
        config = TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)
        assert config.minimum_trust_level == TrustLevel.DEVELOPER

        # Test all trust levels
        for level in TrustLevel:
            config = TrustedFilterConfig(minimum_trust_level=level)
            assert config.minimum_trust_level == level

    def test_disabled_filter(self):
        """Should allow disabling the filter."""
        config = TrustedFilterConfig(enabled=False)
        assert config.enabled is False


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation and behavior."""

    def test_default_values(self):
        """Default config should have sensible values."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.remove_instructions is True
        assert config.max_content_length == 100000

    def test_sanitization_modes(self):
        """Should validate sanitization mode."""
        valid_modes = ["remove", "mask", "escape", "tag"]

        for mode in valid_modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_aggressiveness_levels(self):
        """Should validate aggressiveness levels."""
        valid_levels = ["minimal", "balanced", "aggressive"]

        for level in valid_levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_custom_removal_patterns(self):
        """Should accept custom regex patterns."""
        patterns = [r"evil_pattern_\d+", r"malicious.*content"]
        config = DataFilterConfig(custom_removal_patterns=patterns)

        assert len(config.custom_removal_patterns) == 2
        assert patterns[0] in config.custom_removal_patterns

    def test_max_content_length_boundary(self):
        """Should handle various content length limits."""
        # Small limit
        config = DataFilterConfig(max_content_length=100)
        assert config.max_content_length == 100

        # Large limit
        config = DataFilterConfig(max_content_length=1000000)
        assert config.max_content_length == 1000000

        # Zero should be accepted (no limit)
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0


class TestDetectorConfig:
    """Tests for DetectorConfig validation and behavior."""

    def test_default_values(self):
        """Default config should have sensible values."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.confidence_threshold == 0.7
        assert config.min_risk_level == RiskLevel.LOW
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.context_aware is True

    def test_confidence_threshold_valid_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        for threshold in [0.0, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_confidence_threshold_boundary_values(self):
        """Should handle boundary values for confidence threshold."""
        # Minimum boundary
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

        # Maximum boundary
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

    def test_risk_level_validation(self):
        """Should validate risk level enum values."""
        for level in RiskLevel:
            config = DetectorConfig(min_risk_level=level)
            assert config.min_risk_level == level

    def test_ml_model_settings(self):
        """Should validate ML model settings."""
        config = DetectorConfig(
            ml_model_name="custom/model",
            ml_batch_size=16,
            ml_max_length=1024,
        )

        assert config.ml_model_name == "custom/model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 1024

    def test_custom_patterns(self):
        """Should accept custom detection patterns."""
        custom_patterns = {
            "custom_attack_1": r"evil.*command",
            "custom_attack_2": r"exfiltrate.*data",
        }
        config = DetectorConfig(custom_patterns=custom_patterns)

        assert len(config.custom_patterns) == 2
        assert "custom_attack_1" in config.custom_patterns

    def test_tool_output_sensitivity(self):
        """Should validate tool output sensitivity multiplier."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

        # Should allow values >= 1.0
        config = DetectorConfig(tool_output_sensitivity=2.0)
        assert config.tool_output_sensitivity == 2.0

    def test_component_toggles(self):
        """Should allow disabling detector components."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation and behavior."""

    def test_default_values(self):
        """Default config should have sensible values."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"
        assert config.include_metadata is True

    def test_fence_formats(self):
        """Should validate fence format options."""
        valid_formats = ["xml", "markdown", "json", "delimiter"]

        for fmt in valid_formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_custom_delimiters(self):
        """Should allow custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<TRUSTED>>>",
            trusted_suffix="<<<END>>>",
            untrusted_prefix="<<<UNTRUSTED>>>",
            untrusted_suffix="<<<END_UNTRUSTED>>>",
        )

        assert config.trusted_prefix == "<<<TRUSTED>>>"
        assert config.trusted_suffix == "<<<END>>>"

    def test_signature_algorithms(self):
        """Should accept different signature algorithms."""
        algorithms = ["hmac-sha256", "hmac-sha512", "blake2b"]

        for algo in algorithms:
            config = PromptFenceConfig(signature_algorithm=algo)
            assert config.signature_algorithm == algo


class TestLoggingConfig:
    """Tests for LoggingConfig validation and behavior."""

    def test_default_values(self):
        """Default config should have sensible values."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.log_detections is True
        assert config.redact_content is True
        assert config.max_logged_content_length == 200

    def test_log_levels(self):
        """Should accept standard log levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in levels:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_toggles(self):
        """Should allow toggling different logging aspects."""
        config = LoggingConfig(
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False,
        )

        assert config.log_detections is False
        assert config.log_sanitizations is False
        assert config.log_processing_times is False

    def test_max_logged_content_length(self):
        """Should validate max logged content length."""
        config = LoggingConfig(max_logged_content_length=500)
        assert config.max_logged_content_length == 500

        # Zero means no limit
        config = LoggingConfig(max_logged_content_length=0)
        assert config.max_logged_content_length == 0


class TestMasterConfig:
    """Tests for the master Config class."""

    def test_default_config(self):
        """Default config should instantiate successfully."""
        config = Config.default()

        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None
        assert config.fail_open is False
        assert config.strict_mode is False

    def test_strict_config_preset(self):
        """Strict preset should have more restrictive settings."""
        config = Config.strict()

        # Should be more restrictive
        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_external is False
        assert config.trusted_filter.allow_anonymous is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.5  # Lower = more detections
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_preset(self):
        """Permissive preset should be less restrictive."""
        config = Config.permissive()

        # Should be less restrictive
        assert config.fail_open is True
        assert config.trusted_filter.allow_external is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold == 0.85  # Higher = fewer detections
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_strict_vs_permissive_differences(self):
        """Strict and permissive should have clear differences."""
        strict = Config.strict()
        permissive = Config.permissive()

        # Trust level differences (strict should require higher trust)
        # DEVELOPER is more restrictive than EXTERNAL
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert permissive.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL
        assert strict.trusted_filter.allow_external is False
        assert permissive.trusted_filter.allow_external is True

        # Confidence threshold (strict lower = catches more)
        assert strict.detector.confidence_threshold < permissive.detector.confidence_threshold

        # Block threshold (strict blocks at MEDIUM, permissive at CRITICAL)
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert permissive.block_threshold == RiskLevel.CRITICAL

        # Aggressiveness
        assert strict.data_filter.aggressiveness == "aggressive"
        assert permissive.data_filter.aggressiveness == "minimal"

    def test_custom_config_with_overrides(self):
        """Should allow creating config with custom overrides."""
        config = Config(
            strict_mode=True,
            fail_open=True,
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.MAINTAINER,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.8,
            ),
        )

        assert config.strict_mode is True
        assert config.fail_open is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.MAINTAINER
        assert config.detector.confidence_threshold == 0.8

    def test_performance_settings(self):
        """Should validate performance settings."""
        config = Config(
            enable_caching=False,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=60.0,
        )

        assert config.enable_caching is False
        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 60.0

    def test_threshold_settings(self):
        """Should validate risk threshold settings."""
        config = Config(
            block_threshold=RiskLevel.CRITICAL,
            warn_threshold=RiskLevel.MEDIUM,
        )

        assert config.block_threshold == RiskLevel.CRITICAL
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_nested_config_changes_isolated(self):
        """Changes to one config should not affect another."""
        config1 = Config.default()
        config2 = Config.default()

        # Modify config1
        config1.detector.confidence_threshold = 0.9

        # config2 should be unchanged
        assert config2.detector.confidence_threshold == 0.7

    def test_config_serialization(self):
        """Config should be serializable (for saving/loading)."""
        config = Config.default()

        # Pydantic models should support dict conversion
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

        # Should be able to reconstruct
        reconstructed = Config(**config_dict)
        assert reconstructed.detector.confidence_threshold == config.detector.confidence_threshold


class TestConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_zero_cache_ttl(self):
        """Zero cache TTL should be allowed (no caching)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_very_large_timeout(self):
        """Should handle large timeout values."""
        config = Config(request_timeout_seconds=300.0)
        assert config.request_timeout_seconds == 300.0

    def test_empty_allowlists(self):
        """Empty allowlists should be valid."""
        config = TrustedFilterConfig(
            allowed_users=[],
            allowed_domains=[],
        )
        assert len(config.allowed_users) == 0
        assert len(config.allowed_domains) == 0

    def test_multiple_custom_patterns(self):
        """Should handle many custom patterns."""
        patterns = {f"pattern_{i}": f"regex_{i}" for i in range(100)}
        config = DetectorConfig(custom_patterns=patterns)
        assert len(config.custom_patterns) == 100

    def test_very_short_max_logged_content(self):
        """Should allow very short logged content limits."""
        config = LoggingConfig(max_logged_content_length=10)
        assert config.max_logged_content_length == 10

    def test_all_layers_disabled(self):
        """Should allow disabling all layers (pass-through mode)."""
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

    def test_extreme_confidence_thresholds(self):
        """Should handle extreme confidence threshold values."""
        # Very low (catch everything)
        config = DetectorConfig(confidence_threshold=0.01)
        assert config.confidence_threshold == 0.01

        # Very high (catch almost nothing)
        config = DetectorConfig(confidence_threshold=0.99)
        assert config.confidence_threshold == 0.99
