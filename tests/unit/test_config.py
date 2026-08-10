"""
Unit tests for configuration validation and edge cases.

Tests the Config classes for invalid values, boundary conditions,
and conflicting settings that could lead to security misconfigurations.
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


class TestConfigBoundaryConditions:
    """Tests for configuration boundary conditions and edge cases."""

    def test_detector_confidence_threshold_at_zero(self):
        """Confidence threshold at 0.0 should be valid (matches everything)."""
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

    def test_detector_confidence_threshold_at_one(self):
        """Confidence threshold at 1.0 should be valid (matches nothing)."""
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

    def test_detector_confidence_threshold_negative(self):
        """Negative confidence threshold should fail validation."""
        with pytest.raises(ValidationError):
            DetectorConfig(confidence_threshold=-0.1)

    def test_detector_confidence_threshold_above_one(self):
        """Confidence threshold above 1.0 should fail validation."""
        with pytest.raises(ValidationError):
            DetectorConfig(confidence_threshold=1.1)

    def test_data_filter_max_content_length_zero(self):
        """Zero max content length should be valid (blocks all content)."""
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0

    def test_data_filter_max_content_length_negative(self):
        """Negative max content length should fail validation."""
        with pytest.raises(ValidationError):
            DataFilterConfig(max_content_length=-1)

    def test_cache_ttl_zero(self):
        """Zero cache TTL should be valid (no caching)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_cache_ttl_negative(self):
        """Negative cache TTL should fail validation."""
        with pytest.raises(ValidationError):
            Config(cache_ttl_seconds=-1)

    def test_request_timeout_zero(self):
        """Zero timeout should fail validation (would timeout immediately)."""
        with pytest.raises(ValidationError):
            Config(request_timeout_seconds=0.0)

    def test_request_timeout_negative(self):
        """Negative timeout should fail validation."""
        with pytest.raises(ValidationError):
            Config(request_timeout_seconds=-1.0)

    def test_max_concurrent_requests_zero(self):
        """Zero concurrent requests should fail validation."""
        with pytest.raises(ValidationError):
            Config(max_concurrent_requests=0)

    def test_max_concurrent_requests_negative(self):
        """Negative concurrent requests should fail validation."""
        with pytest.raises(ValidationError):
            Config(max_concurrent_requests=-1)

    def test_logging_max_content_length_zero(self):
        """Zero max logged content length should be valid (no content logged)."""
        config = LoggingConfig(max_logged_content_length=0)
        assert config.max_logged_content_length == 0

    def test_ml_batch_size_zero(self):
        """Zero ML batch size should fail validation."""
        with pytest.raises(ValidationError):
            DetectorConfig(ml_batch_size=0)

    def test_ml_max_length_zero(self):
        """Zero ML max length should fail validation."""
        with pytest.raises(ValidationError):
            DetectorConfig(ml_max_length=0)


class TestConfigInvalidValues:
    """Tests for invalid configuration values."""

    def test_invalid_sanitization_mode(self):
        """Invalid sanitization mode should fail validation."""
        with pytest.raises(ValidationError):
            DataFilterConfig(mode="invalid_mode")

    def test_valid_sanitization_modes(self):
        """All valid sanitization modes should work."""
        valid_modes = ["remove", "mask", "escape", "tag"]
        for mode in valid_modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_invalid_aggressiveness(self):
        """Invalid aggressiveness level should fail validation."""
        with pytest.raises(ValidationError):
            DataFilterConfig(aggressiveness="super_aggressive")

    def test_valid_aggressiveness_levels(self):
        """All valid aggressiveness levels should work."""
        valid_levels = ["minimal", "balanced", "aggressive"]
        for level in valid_levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_invalid_fence_format(self):
        """Invalid fence format should fail validation."""
        with pytest.raises(ValidationError):
            PromptFenceConfig(fence_format="invalid")

    def test_valid_fence_formats(self):
        """All valid fence formats should work."""
        valid_formats = ["xml", "markdown", "json", "delimiter"]
        for fmt in valid_formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_invalid_signature_algorithm(self):
        """Invalid signature algorithm should fail validation."""
        with pytest.raises(ValidationError):
            PromptFenceConfig(signature_algorithm="md5")  # Weak algorithm

    def test_valid_signature_algorithms(self):
        """Valid signature algorithms should work."""
        valid_algos = ["hmac-sha256", "hmac-sha512"]
        for algo in valid_algos:
            config = PromptFenceConfig(signature_algorithm=algo)
            assert config.signature_algorithm == algo

    def test_invalid_log_level(self):
        """Invalid log level should fail validation."""
        with pytest.raises(ValidationError):
            LoggingConfig(log_level="INVALID")

    def test_valid_log_levels(self):
        """All valid log levels should work."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level


class TestConfigConflictingSettings:
    """Tests for conflicting or contradictory configuration settings."""

    def test_strict_mode_with_fail_open(self):
        """Strict mode with fail_open=True is contradictory but allowed."""
        # This is a warning-level issue, not an error
        config = Config(strict_mode=True, fail_open=True)
        assert config.strict_mode is True
        assert config.fail_open is True

    def test_disabled_all_detector_components(self):
        """Disabling all detector components should be allowed."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )
        # This makes the detector useless but might be intentional for testing
        assert not config.use_pattern_matching
        assert not config.use_ml_model
        assert not config.use_heuristics

    def test_disabled_layer_with_enabled_pipeline(self):
        """Can disable individual layers in enabled pipeline."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False),
        )
        # All layers disabled - pipeline effectively does nothing
        assert not config.trusted_filter.enabled
        assert not config.data_filter.enabled
        assert not config.detector.enabled
        assert not config.prompt_fence.enabled

    def test_allow_anonymous_but_block_external(self):
        """Allowing anonymous but not external is logically odd."""
        # Anonymous is typically less trusted than external
        config = TrustedFilterConfig(
            allow_anonymous=True,
            allow_external=False,
        )
        assert config.allow_anonymous
        assert not config.allow_external

    def test_high_confidence_threshold_with_high_sensitivity(self):
        """High confidence threshold with high sensitivity might cause issues."""
        config = DetectorConfig(
            confidence_threshold=0.95,
            tool_output_sensitivity=2.0,
        )
        # This is valid but might be too strict
        assert config.confidence_threshold == 0.95
        assert config.tool_output_sensitivity == 2.0

    def test_redact_content_disabled_but_logging_enabled(self):
        """Redaction disabled with logging could leak sensitive data."""
        config = LoggingConfig(
            enabled=True,
            redact_content=False,
        )
        # This is a security risk but technically valid
        assert config.enabled
        assert not config.redact_content


class TestConfigPresets:
    """Tests for configuration presets (default, strict, permissive)."""

    def test_default_preset_values(self):
        """Default preset should have balanced settings."""
        config = Config.default()

        assert config.fail_open is False
        assert config.strict_mode is False
        assert config.trusted_filter.allow_external is True
        assert config.trusted_filter.allow_anonymous is False
        assert config.data_filter.aggressiveness == "balanced"
        assert config.detector.confidence_threshold == 0.7
        assert config.block_threshold == RiskLevel.HIGH

    def test_strict_preset_values(self):
        """Strict preset should have restrictive settings."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False
        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.5
        assert config.detector.tool_output_sensitivity == 1.5
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_preset_values(self):
        """Permissive preset should have relaxed settings."""
        config = Config.permissive()

        assert config.fail_open is True
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True
        assert config.data_filter.aggressiveness == "minimal"
        assert config.detector.confidence_threshold == 0.85
        assert config.detector.tool_output_sensitivity == 1.0
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_strict_preset_more_restrictive_than_default(self):
        """Strict should be more restrictive than default."""
        strict = Config.strict()
        default = Config.default()

        # Strict should have higher trust requirements
        assert strict.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert default.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL
        # Strict should have lower confidence threshold (more sensitive)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold
        # Strict should block at lower risk level (MEDIUM vs HIGH)
        assert strict.block_threshold == RiskLevel.MEDIUM
        assert default.block_threshold == RiskLevel.HIGH

    def test_permissive_preset_more_relaxed_than_default(self):
        """Permissive should be more relaxed than default."""
        permissive = Config.permissive()
        default = Config.default()

        # Permissive should allow anonymous
        assert permissive.trusted_filter.allow_anonymous
        assert not default.trusted_filter.allow_anonymous
        # Permissive should have higher confidence threshold (less sensitive)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold
        # Permissive should block at higher risk level (CRITICAL vs HIGH)
        assert permissive.block_threshold == RiskLevel.CRITICAL
        assert default.block_threshold == RiskLevel.HIGH


class TestCustomPatternValidation:
    """Tests for custom pattern validation."""

    def test_empty_custom_patterns(self):
        """Empty custom patterns should be valid."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_valid_custom_patterns(self):
        """Valid regex patterns should be accepted."""
        patterns = {
            "test_pattern": r"test\s+pattern",
            "email_pattern": r"\S+@\S+\.\S+",
        }
        config = DetectorConfig(custom_patterns=patterns)
        assert config.custom_patterns == patterns

    def test_invalid_regex_in_custom_patterns(self):
        """Invalid regex should fail at compile time, not config time."""
        # Pydantic doesn't validate regex syntax at config creation
        invalid_patterns = {
            "bad_pattern": r"[unclosed",  # Invalid regex
        }
        config = DetectorConfig(custom_patterns=invalid_patterns)
        # Config creation succeeds; regex compilation would fail later
        assert "bad_pattern" in config.custom_patterns

    def test_empty_custom_removal_patterns(self):
        """Empty custom removal patterns should be valid."""
        config = DataFilterConfig(custom_removal_patterns=[])
        assert config.custom_removal_patterns == []

    def test_multiple_custom_removal_patterns(self):
        """Multiple custom removal patterns should be accepted."""
        patterns = [
            r"REMOVE_THIS",
            r"\[HIDDEN\].*?\[/HIDDEN\]",
        ]
        config = DataFilterConfig(custom_removal_patterns=patterns)
        assert config.custom_removal_patterns == patterns


class TestAllowBlockLists:
    """Tests for allowlist/blocklist configuration."""

    def test_empty_allow_block_lists(self):
        """Empty lists should be valid."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
            allowed_domains=[],
            blocked_domains=[],
        )
        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []

    def test_populated_allow_lists(self):
        """Populated allowlists should work."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            allowed_domains=["trusted.com", "example.org"],
        )
        assert "alice" in config.allowed_users
        assert "trusted.com" in config.allowed_domains

    def test_populated_block_lists(self):
        """Populated blocklists should work."""
        config = TrustedFilterConfig(
            blocked_users=["mallory", "eve"],
            blocked_domains=["evil.com", "malicious.net"],
        )
        assert "mallory" in config.blocked_users
        assert "evil.com" in config.blocked_domains

    def test_overlapping_allow_and_block_users(self):
        """Same user in both allow and block lists (edge case)."""
        config = TrustedFilterConfig(
            allowed_users=["alice"],
            blocked_users=["alice"],
        )
        # This is contradictory but allowed at config level
        # Resolution would happen at runtime
        assert "alice" in config.allowed_users
        assert "alice" in config.blocked_users

    def test_overlapping_allow_and_block_domains(self):
        """Same domain in both allow and block lists (edge case)."""
        config = TrustedFilterConfig(
            allowed_domains=["example.com"],
            blocked_domains=["example.com"],
        )
        # This is contradictory but allowed at config level
        assert "example.com" in config.allowed_domains
        assert "example.com" in config.blocked_domains


class TestConfigSerialization:
    """Tests for configuration serialization/deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict

    def test_config_from_dict(self):
        """Config should deserialize from dict."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
            "trusted_filter": {
                "enabled": True,
                "allow_anonymous": False,
            },
        }
        config = Config(**config_dict)

        assert config.strict_mode is True
        assert config.fail_open is False
        assert config.trusted_filter.allow_anonymous is False

    def test_config_roundtrip(self):
        """Config should survive serialization roundtrip."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold
        assert restored.block_threshold == original.block_threshold

    def test_partial_config_dict(self):
        """Partial config dict should merge with defaults."""
        config_dict = {
            "strict_mode": True,
        }
        config = Config(**config_dict)

        # Specified field
        assert config.strict_mode is True
        # Default fields
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True


class TestSecurityMisconfigurationEdgeCases:
    """Tests for security-critical misconfigurations."""

    def test_all_layers_disabled_creates_bypass(self):
        """Disabling all layers creates a security bypass."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False),
        )

        # All layers disabled - this is a total bypass
        layers_enabled = [
            config.trusted_filter.enabled,
            config.data_filter.enabled,
            config.detector.enabled,
            config.prompt_fence.enabled,
        ]
        assert not any(layers_enabled)

    def test_allow_anonymous_with_no_detection(self):
        """Allowing anonymous with detector disabled is risky."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allow_anonymous=True,
                allow_external=True,
            ),
            detector=DetectorConfig(enabled=False),
        )

        # This allows all anonymous content with no detection
        assert config.trusted_filter.allow_anonymous
        assert not config.detector.enabled

    def test_fail_open_with_critical_threshold(self):
        """Fail-open with critical threshold means most attacks pass."""
        config = Config(
            fail_open=True,
            block_threshold=RiskLevel.CRITICAL,
        )

        # Only blocks CRITICAL risks, and fails open on errors
        assert config.fail_open
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_signatures_disabled_removes_integrity_check(self):
        """Disabling signatures removes fence integrity protection."""
        config = PromptFenceConfig(use_signatures=False)

        assert not config.use_signatures

    def test_context_awareness_disabled_misses_indirect_attacks(self):
        """Disabling context awareness defeats indirect injection detection."""
        config = DetectorConfig(context_aware=False)

        assert not config.context_aware

    def test_minimum_trust_level_anonymous_allows_everyone(self):
        """Setting minimum trust to ANONYMOUS allows everyone."""
        config = TrustedFilterConfig(
            minimum_trust_level=TrustLevel.ANONYMOUS,
            allow_anonymous=True,
        )

        # This is the most permissive setting
        assert config.minimum_trust_level == TrustLevel.ANONYMOUS
        assert config.allow_anonymous
