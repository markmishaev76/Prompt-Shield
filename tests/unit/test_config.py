"""
Unit tests for configuration validation.

Tests the Config class and its factory methods to ensure
security-critical configuration parameters are validated correctly.
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


class TestConfigFactoryMethods:
    """Tests for Config factory methods."""

    def test_default_config_creation(self):
        """Default config should be created without errors."""
        config = Config.default()

        assert config is not None
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_strict_config_creation(self):
        """Strict config should be more restrictive."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.5
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_creation(self):
        """Permissive config should be less restrictive."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold == 0.85
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_strict_more_restrictive_than_default(self):
        """Strict config should have lower thresholds than default."""
        default = Config.default()
        strict = Config.strict()

        # Strict should have lower confidence threshold (catches more)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Strict should block at lower risk level (MEDIUM < HIGH)
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(strict.block_threshold) < risk_order.index(default.block_threshold)

    def test_permissive_less_restrictive_than_default(self):
        """Permissive config should have higher thresholds than default."""
        default = Config.default()
        permissive = Config.permissive()

        # Permissive should have higher confidence threshold (catches less)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Permissive should block at higher risk level (CRITICAL > HIGH)
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(permissive.block_threshold) > risk_order.index(default.block_threshold)


class TestTrustedFilterConfigValidation:
    """Tests for TrustedFilterConfig validation."""

    def test_valid_trust_level(self):
        """Valid trust level should be accepted."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.DEVELOPER
        )
        assert config.minimum_trust_level == TrustLevel.DEVELOPER

    def test_allowed_users_list(self):
        """Allowed users list should be stored correctly."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob", "charlie"]
        )
        assert len(config.allowed_users) == 3
        assert "alice" in config.allowed_users

    def test_blocked_users_list(self):
        """Blocked users list should be stored correctly."""
        config = TrustedFilterConfig(
            blocked_users=["attacker1", "attacker2"]
        )
        assert len(config.blocked_users) == 2
        assert "attacker1" in config.blocked_users

    def test_empty_lists_default(self):
        """Empty lists should be default for allow/block lists."""
        config = TrustedFilterConfig()
        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []

    def test_conflicting_allow_external_settings(self):
        """Config should handle conflicting external settings."""
        # Both allow_anonymous and allow_external False is valid
        config = TrustedFilterConfig(
            allow_anonymous=False,
            allow_external=False
        )
        assert config.allow_anonymous is False
        assert config.allow_external is False

        # Allow anonymous but not external is a strange config but valid
        config2 = TrustedFilterConfig(
            allow_anonymous=True,
            allow_external=False
        )
        assert config2.allow_anonymous is True


class TestDataFilterConfigValidation:
    """Tests for DataFilterConfig validation."""

    def test_valid_sanitization_modes(self):
        """Valid sanitization modes should be accepted."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness_levels(self):
        """Valid aggressiveness levels should be accepted."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_positive(self):
        """Max content length should be positive."""
        config = DataFilterConfig(max_content_length=50000)
        assert config.max_content_length == 50000

    def test_custom_removal_patterns(self):
        """Custom removal patterns should be stored."""
        patterns = [r"\[SECRET\].*?\[/SECRET\]", r"password:\s*\S+"]
        config = DataFilterConfig(custom_removal_patterns=patterns)
        assert len(config.custom_removal_patterns) == 2

    def test_preservation_flags(self):
        """Preservation flags should work correctly."""
        config = DataFilterConfig(
            preserve_code_context=False,
            preserve_documentation=False
        )
        assert config.preserve_code_context is False
        assert config.preserve_documentation is False


class TestDetectorConfigValidation:
    """Tests for DetectorConfig validation."""

    def test_confidence_threshold_valid_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid values
        for threshold in [0.0, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_confidence_threshold_boundary(self):
        """Test confidence threshold at boundaries."""
        # Minimum boundary
        config_min = DetectorConfig(confidence_threshold=0.0)
        assert config_min.confidence_threshold == 0.0

        # Maximum boundary
        config_max = DetectorConfig(confidence_threshold=1.0)
        assert config_max.confidence_threshold == 1.0

    def test_valid_risk_levels(self):
        """Valid risk levels should be accepted."""
        for risk in [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            config = DetectorConfig(min_risk_level=risk)
            assert config.min_risk_level == risk

    def test_detector_components_flags(self):
        """Detector component flags should work independently."""
        config = DetectorConfig(
            use_pattern_matching=True,
            use_ml_model=False,
            use_heuristics=True
        )
        assert config.use_pattern_matching is True
        assert config.use_ml_model is False
        assert config.use_heuristics is True

    def test_all_components_disabled(self):
        """Config should allow all components disabled (edge case)."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False
        )
        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_tool_output_sensitivity_multiplier(self):
        """Tool output sensitivity should be >= 1.0."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

        # Value of 1.0 means no multiplier
        config2 = DetectorConfig(tool_output_sensitivity=1.0)
        assert config2.tool_output_sensitivity == 1.0

    def test_custom_patterns_dict(self):
        """Custom patterns should be stored as dict."""
        patterns = {
            "custom_exfil": r"send.*to.*attacker\.com",
            "custom_backdoor": r"create.*backdoor.*account"
        }
        config = DetectorConfig(custom_patterns=patterns)
        assert len(config.custom_patterns) == 2
        assert "custom_exfil" in config.custom_patterns

    def test_ml_model_settings(self):
        """ML model settings should be configurable."""
        config = DetectorConfig(
            ml_model_name="custom-model",
            ml_batch_size=16,
            ml_max_length=1024
        )
        assert config.ml_model_name == "custom-model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 1024


class TestPromptFenceConfigValidation:
    """Tests for PromptFenceConfig validation."""

    def test_valid_fence_formats(self):
        """Valid fence formats should be accepted."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_signature_settings(self):
        """Signature settings should work correctly."""
        config = PromptFenceConfig(
            use_signatures=True,
            signature_algorithm="hmac-sha256"
        )
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"

    def test_custom_delimiters(self):
        """Custom fence delimiters should be configurable."""
        config = PromptFenceConfig(
            trusted_prefix="[TRUSTED]",
            trusted_suffix="[/TRUSTED]",
            untrusted_prefix="[UNTRUSTED]",
            untrusted_suffix="[/UNTRUSTED]"
        )
        assert config.trusted_prefix == "[TRUSTED]"
        assert config.trusted_suffix == "[/TRUSTED]"

    def test_metadata_flags(self):
        """Metadata inclusion flags should work."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True
        )
        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True


class TestLoggingConfigValidation:
    """Tests for LoggingConfig validation."""

    def test_valid_log_levels(self):
        """Valid log levels should be accepted."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_flags(self):
        """Logging flags should be independently configurable."""
        config = LoggingConfig(
            log_detections=True,
            log_sanitizations=False,
            log_processing_times=True
        )
        assert config.log_detections is True
        assert config.log_sanitizations is False
        assert config.log_processing_times is True

    def test_content_redaction(self):
        """Content redaction settings should work."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100
        )
        assert config.redact_content is True
        assert config.max_logged_content_length == 100


class TestMasterConfigValidation:
    """Tests for master Config class."""

    def test_config_with_all_layers(self):
        """Config should include all layer configurations."""
        config = Config()

        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None

    def test_fail_open_setting(self):
        """Fail open setting should affect error handling."""
        # Fail closed (default - more secure)
        config_closed = Config(fail_open=False)
        assert config_closed.fail_open is False

        # Fail open (less secure but more available)
        config_open = Config(fail_open=True)
        assert config_open.fail_open is True

    def test_strict_mode_setting(self):
        """Strict mode should be configurable."""
        config = Config(strict_mode=True)
        assert config.strict_mode is True

    def test_risk_thresholds(self):
        """Risk thresholds should be configurable."""
        config = Config(
            block_threshold=RiskLevel.HIGH,
            warn_threshold=RiskLevel.MEDIUM
        )
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_performance_settings(self):
        """Performance settings should be configurable."""
        config = Config(
            enable_caching=True,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=60.0
        )
        assert config.enable_caching is True
        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 60.0

    def test_logical_threshold_ordering(self):
        """Block threshold should be >= warn threshold."""
        # Valid: block at HIGH, warn at MEDIUM
        config = Config(
            block_threshold=RiskLevel.HIGH,
            warn_threshold=RiskLevel.MEDIUM
        )
        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert risk_order.index(config.block_threshold) >= risk_order.index(config.warn_threshold)

    def test_config_serialization(self):
        """Config should be serializable to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Config should be creatable from dict."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
            "block_threshold": "high",
            "warn_threshold": "medium",
        }

        config = Config(**config_dict)
        assert config.strict_mode is True
        assert config.fail_open is False


class TestConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_zero_cache_ttl(self):
        """Zero cache TTL should be valid (no caching)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_zero_timeout(self):
        """Zero timeout should be valid (no timeout)."""
        config = Config(request_timeout_seconds=0.0)
        assert config.request_timeout_seconds == 0.0

    def test_very_large_content_length(self):
        """Very large content length should be accepted."""
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_empty_custom_patterns(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_all_layers_disabled(self):
        """Config should allow all layers disabled (extreme edge case)."""
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


class TestConfigSecurityImplications:
    """Tests for security-critical configuration combinations."""

    def test_dangerous_permissive_combination(self):
        """Test that extremely permissive config is still valid."""
        # This is a dangerous but valid config
        config = Config(
            fail_open=True,
            trusted_filter=TrustedFilterConfig(
                enabled=False,
                allow_anonymous=True,
                allow_external=True,
            ),
            detector=DetectorConfig(
                enabled=False,
            ),
            block_threshold=RiskLevel.CRITICAL,
        )

        # Should be valid but risky
        assert config.trusted_filter.enabled is False
        assert config.detector.enabled is False

    def test_secure_strict_combination(self):
        """Test that strict secure config is valid."""
        config = Config(
            fail_open=False,
            strict_mode=True,
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.MAINTAINER,
                allow_anonymous=False,
                allow_external=False,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.4,
            ),
            block_threshold=RiskLevel.LOW,
        )

        # Should be very strict
        assert config.fail_open is False
        assert config.strict_mode is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.MAINTAINER
        assert config.block_threshold == RiskLevel.LOW

    def test_detector_disabled_with_strict_mode(self):
        """Strict mode with detector disabled should still be valid."""
        # This is an odd combination but valid
        config = Config(
            strict_mode=True,
            detector=DetectorConfig(enabled=False),
        )

        assert config.strict_mode is True
        assert config.detector.enabled is False
