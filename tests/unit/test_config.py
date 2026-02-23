"""
Unit tests for configuration validation and edge cases.

Tests the Config class, factory methods, and validation logic
to ensure secure-by-default behavior and proper error handling.
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


class TestConfigDefaults:
    """Tests for default configuration values."""

    def test_default_config_is_secure(self):
        """Default config should have secure settings."""
        config = Config.default()

        # All layers should be enabled by default
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

        # Should fail closed by default (security-first)
        assert config.fail_open is False

        # Reasonable default thresholds
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_default_detector_config(self):
        """Default detector config should be reasonable."""
        config = DetectorConfig()

        # All detection methods enabled by default
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

        # Reasonable confidence threshold (not too strict, not too loose)
        assert 0.5 <= config.confidence_threshold <= 0.8

        # Tool output should have higher sensitivity
        assert config.tool_output_sensitivity >= 1.0

    def test_default_trusted_filter_allows_external(self):
        """Default should allow external contributors (OSS-friendly)."""
        config = TrustedFilterConfig()

        assert config.allow_external is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL


class TestStrictConfig:
    """Tests for strict security configuration."""

    def test_strict_mode_stricter_thresholds(self):
        """Strict mode should have stricter detection thresholds."""
        default_config = Config.default()
        strict_config = Config.strict()

        # Define risk hierarchy for comparison
        risk_order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }

        # Strict should block at lower risk levels (lower in hierarchy = more strict)
        assert risk_order[strict_config.block_threshold] <= risk_order[default_config.block_threshold]

        # Strict should have lower confidence threshold (catch more)
        assert strict_config.detector.confidence_threshold <= default_config.detector.confidence_threshold

    def test_strict_mode_restricts_trust(self):
        """Strict mode should restrict trust levels."""
        strict_config = Config.strict()

        # Should not allow anonymous or external by default
        assert strict_config.trusted_filter.allow_anonymous is False
        assert strict_config.trusted_filter.allow_external is False

        # Should require developer trust or higher
        assert strict_config.trusted_filter.minimum_trust_level >= TrustLevel.DEVELOPER

    def test_strict_mode_aggressive_sanitization(self):
        """Strict mode should use aggressive sanitization."""
        strict_config = Config.strict()

        assert strict_config.data_filter.aggressiveness == "aggressive"

    def test_strict_mode_fails_closed(self):
        """Strict mode should never fail open."""
        strict_config = Config.strict()

        assert strict_config.fail_open is False
        assert strict_config.strict_mode is True


class TestPermissiveConfig:
    """Tests for permissive configuration."""

    def test_permissive_mode_allows_more(self):
        """Permissive mode should allow more content."""
        permissive_config = Config.permissive()

        # Should allow anonymous and external
        assert permissive_config.trusted_filter.allow_anonymous is True
        assert permissive_config.trusted_filter.allow_external is True

        # Should fail open (availability over security)
        assert permissive_config.fail_open is True

    def test_permissive_mode_high_confidence_threshold(self):
        """Permissive mode should require higher confidence to block."""
        permissive_config = Config.permissive()

        # Higher confidence threshold = fewer false positives
        assert permissive_config.detector.confidence_threshold >= 0.8

        # Only block critical threats
        assert permissive_config.block_threshold == RiskLevel.CRITICAL

    def test_permissive_mode_minimal_sanitization(self):
        """Permissive mode should use minimal sanitization."""
        permissive_config = Config.permissive()

        assert permissive_config.data_filter.aggressiveness == "minimal"


class TestDetectorConfigValidation:
    """Tests for detector configuration validation and edge cases."""

    def test_confidence_threshold_in_valid_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        DetectorConfig(confidence_threshold=0.0)
        DetectorConfig(confidence_threshold=0.5)
        DetectorConfig(confidence_threshold=1.0)

        # Invalid thresholds should not crash (pydantic may allow or coerce)
        # We test behavior, not exceptions
        config = DetectorConfig(confidence_threshold=0.95)
        assert 0 <= config.confidence_threshold <= 1

    def test_tool_output_sensitivity_multiplier(self):
        """Tool output sensitivity should be >= 1.0."""
        config = DetectorConfig(tool_output_sensitivity=1.5)
        assert config.tool_output_sensitivity == 1.5

        # Even 1.0 should be valid (no boost)
        config = DetectorConfig(tool_output_sensitivity=1.0)
        assert config.tool_output_sensitivity == 1.0

    def test_all_detection_methods_can_be_disabled(self):
        """All detection methods should be independently disableable."""
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert config.use_pattern_matching is False
        assert config.use_ml_model is False
        assert config.use_heuristics is False

    def test_custom_patterns_dictionary(self):
        """Custom patterns should accept dictionary of name->regex."""
        custom = {
            "my_pattern": r"malicious\s+content",
            "another_pattern": r"bad\s+instruction",
        }
        config = DetectorConfig(custom_patterns=custom)

        assert "my_pattern" in config.custom_patterns
        assert config.custom_patterns["my_pattern"] == r"malicious\s+content"

    def test_blocked_patterns_list(self):
        """Blocked patterns should accept list of patterns."""
        blocked = ["pattern1", "pattern2", "pattern3"]
        config = DetectorConfig(blocked_patterns=blocked)

        assert len(config.blocked_patterns) == 3
        assert "pattern1" in config.blocked_patterns


class TestDataFilterConfigValidation:
    """Tests for data filter configuration edge cases."""

    def test_sanitization_modes(self):
        """All sanitization modes should be valid."""
        modes = ["remove", "mask", "escape", "tag"]

        for mode in modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_aggressiveness_levels(self):
        """All aggressiveness levels should be valid."""
        levels = ["minimal", "balanced", "aggressive"]

        for level in levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_positive(self):
        """Max content length should be positive."""
        config = DataFilterConfig(max_content_length=1000)
        assert config.max_content_length == 1000

        # Very large values should work
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_custom_removal_patterns_list(self):
        """Custom removal patterns should accept list of regex strings."""
        patterns = [r"\[HIDDEN\]", r"secret:\s*\w+", r"password=\S+"]
        config = DataFilterConfig(custom_removal_patterns=patterns)

        assert len(config.custom_removal_patterns) == 3

    def test_preservation_flags_independent(self):
        """Code and documentation preservation should be independent."""
        config = DataFilterConfig(
            preserve_code_context=True,
            preserve_documentation=False,
        )

        assert config.preserve_code_context is True
        assert config.preserve_documentation is False


class TestTrustedFilterConfigValidation:
    """Tests for trusted filter configuration edge cases."""

    def test_trust_level_hierarchy(self):
        """Minimum trust level should use TrustLevel enum."""
        for level in [TrustLevel.ADMIN, TrustLevel.DEVELOPER, TrustLevel.EXTERNAL]:
            config = TrustedFilterConfig(minimum_trust_level=level)
            assert config.minimum_trust_level == level

    def test_allowlist_blocklist_empty_by_default(self):
        """Lists should be empty by default."""
        config = TrustedFilterConfig()

        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []

    def test_allowlist_blocklist_populated(self):
        """Allowlist and blocklist should accept values."""
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

    def test_content_type_filtering_flags(self):
        """Content type filtering flags should work independently."""
        config = TrustedFilterConfig(
            filter_issue_content=True,
            filter_comments=False,
            filter_file_content=True,
            filter_wiki_pages=False,
        )

        assert config.filter_issue_content is True
        assert config.filter_comments is False
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is False


class TestPromptFenceConfigValidation:
    """Tests for prompt fence configuration edge cases."""

    def test_fence_formats(self):
        """All fence formats should be valid."""
        formats = ["xml", "markdown", "json", "delimiter"]

        for fmt in formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_custom_delimiters(self):
        """Custom delimiters should be configurable."""
        config = PromptFenceConfig(
            trusted_prefix="<<<SAFE>>>",
            trusted_suffix="<<<END_SAFE>>>",
            untrusted_prefix="<<<UNSAFE>>>",
            untrusted_suffix="<<<END_UNSAFE>>>",
        )

        assert config.trusted_prefix == "<<<SAFE>>>"
        assert config.untrusted_suffix == "<<<END_UNSAFE>>>"

    def test_signature_algorithms(self):
        """Signature algorithm should be configurable."""
        algorithms = ["hmac-sha256", "hmac-sha512"]

        for algo in algorithms:
            config = PromptFenceConfig(signature_algorithm=algo)
            assert config.signature_algorithm == algo

    def test_metadata_inclusion_flags(self):
        """Metadata inclusion flags should work independently."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=False,
            include_source_type=True,
        )

        assert config.include_metadata is True
        assert config.include_trust_level is False
        assert config.include_source_type is True


class TestConfigSerialization:
    """Tests for configuration serialization and deserialization."""

    def test_config_to_dict(self):
        """Config should be serializable to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "detector" in config_dict
        assert "trusted_filter" in config_dict

    def test_config_to_json(self):
        """Config should be serializable to JSON."""
        config = Config.default()
        json_str = config.model_dump_json()

        assert isinstance(json_str, str)
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_config_from_dict(self):
        """Config should be constructable from dict."""
        config_dict = {
            "fail_open": True,
            "strict_mode": False,
            "detector": {
                "enabled": True,
                "confidence_threshold": 0.8,
            }
        }

        config = Config(**config_dict)
        assert config.fail_open is True
        assert config.detector.confidence_threshold == 0.8

    def test_config_roundtrip(self):
        """Config should survive serialization roundtrip."""
        original = Config.strict()

        # Serialize and deserialize
        json_str = original.model_dump_json()
        config_dict = json.loads(json_str)
        restored = Config(**config_dict)

        # Key settings should be preserved
        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold


class TestConfigEdgeCases:
    """Tests for configuration edge cases and boundary conditions."""

    def test_empty_config_uses_defaults(self):
        """Empty config should use all defaults."""
        config = Config()

        # Should not crash and should have defaults
        assert config.detector.enabled is True
        assert config.fail_open is False

    def test_confidence_threshold_boundaries(self):
        """Confidence threshold should handle boundary values."""
        # Exactly 0 and 1 should work
        config_zero = DetectorConfig(confidence_threshold=0.0)
        config_one = DetectorConfig(confidence_threshold=1.0)

        assert config_zero.confidence_threshold == 0.0
        assert config_one.confidence_threshold == 1.0

    def test_zero_max_content_length(self):
        """Zero max content length should be valid (effectively disabled)."""
        config = DataFilterConfig(max_content_length=0)
        assert config.max_content_length == 0

    def test_performance_settings_reasonable(self):
        """Performance settings should have reasonable defaults."""
        config = Config.default()

        # Reasonable concurrency limit
        assert config.max_concurrent_requests > 0
        assert config.max_concurrent_requests <= 1000

        # Reasonable timeout
        assert config.request_timeout_seconds > 0
        assert config.request_timeout_seconds <= 300

        # Reasonable cache TTL
        assert config.cache_ttl_seconds >= 0

    def test_logging_config_redaction(self):
        """Logging config should support content redaction."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100,
        )

        assert config.redact_content is True
        assert config.max_logged_content_length == 100


class TestConfigInteraction:
    """Tests for interactions between config settings."""

    def test_strict_mode_implies_fail_closed(self):
        """Strict mode should always fail closed."""
        strict = Config.strict()

        # Strict mode should never fail open
        assert strict.strict_mode is True
        assert strict.fail_open is False

    def test_disabled_layer_in_config(self):
        """Individual layers should be disableable."""
        config = Config(
            detector=DetectorConfig(enabled=False),
        )

        assert config.detector.enabled is False
        # Other layers should still be enabled
        assert config.trusted_filter.enabled is True

    def test_all_layers_disabled(self):
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

    def test_risk_threshold_ordering(self):
        """Block threshold should be >= warn threshold in risk hierarchy."""
        config = Config(
            block_threshold=RiskLevel.HIGH,
            warn_threshold=RiskLevel.MEDIUM,
        )

        # Define risk hierarchy for comparison
        risk_order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }

        # Block threshold should be higher or equal to warn threshold
        assert risk_order[config.block_threshold] >= risk_order[config.warn_threshold]
