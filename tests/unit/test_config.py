"""
Unit tests for configuration module.

Tests configuration validation, presets, and edge cases.
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

    def test_default_config_creation(self):
        """Default config should create successfully."""
        config = Config.default()
        assert config is not None
        assert isinstance(config, Config)

    def test_default_config_has_all_layers(self):
        """Default config should enable all layers."""
        config = Config.default()
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

    def test_default_block_threshold(self):
        """Default config should block HIGH risk and above."""
        config = Config.default()
        assert config.block_threshold == RiskLevel.HIGH

    def test_default_warn_threshold(self):
        """Default config should warn on MEDIUM risk and above."""
        config = Config.default()
        assert config.warn_threshold == RiskLevel.MEDIUM


class TestStrictPreset:
    """Tests for strict security preset."""

    def test_strict_config_creation(self):
        """Strict config should create successfully."""
        config = Config.strict()
        assert config is not None
        assert config.strict_mode is True

    def test_strict_fail_closed(self):
        """Strict config should fail closed."""
        config = Config.strict()
        assert config.fail_open is False

    def test_strict_trust_requirements(self):
        """Strict config should require DEVELOPER trust level."""
        config = Config.strict()
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False

    def test_strict_data_filter_aggressive(self):
        """Strict config should use aggressive sanitization."""
        config = Config.strict()
        assert config.data_filter.aggressiveness == "aggressive"

    def test_strict_detector_lower_threshold(self):
        """Strict config should have lower detection threshold."""
        config = Config.strict()
        assert config.detector.confidence_threshold == 0.5
        assert config.detector.tool_output_sensitivity == 1.5

    def test_strict_block_threshold_medium(self):
        """Strict config should block MEDIUM risk and above."""
        config = Config.strict()
        assert config.block_threshold == RiskLevel.MEDIUM


class TestPermissivePreset:
    """Tests for permissive preset."""

    def test_permissive_config_creation(self):
        """Permissive config should create successfully."""
        config = Config.permissive()
        assert config is not None

    def test_permissive_fail_open(self):
        """Permissive config should fail open."""
        config = Config.permissive()
        assert config.fail_open is True

    def test_permissive_trust_requirements(self):
        """Permissive config should allow all users."""
        config = Config.permissive()
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True

    def test_permissive_data_filter_minimal(self):
        """Permissive config should use minimal sanitization."""
        config = Config.permissive()
        assert config.data_filter.aggressiveness == "minimal"

    def test_permissive_detector_higher_threshold(self):
        """Permissive config should have higher detection threshold."""
        config = Config.permissive()
        assert config.detector.confidence_threshold == 0.85
        assert config.detector.tool_output_sensitivity == 1.0

    def test_permissive_block_threshold_critical(self):
        """Permissive config should only block CRITICAL risk."""
        config = Config.permissive()
        assert config.block_threshold == RiskLevel.CRITICAL


class TestTrustedFilterConfig:
    """Tests for trusted filter configuration."""

    def test_default_minimum_trust_level(self):
        """Default should accept EXTERNAL contributors."""
        config = TrustedFilterConfig()
        assert config.minimum_trust_level == TrustLevel.EXTERNAL

    def test_custom_minimum_trust_level(self):
        """Should accept custom minimum trust level."""
        config = TrustedFilterConfig(minimum_trust_level=TrustLevel.ADMIN)
        assert config.minimum_trust_level == TrustLevel.ADMIN

    def test_default_allows_external(self):
        """Default should allow external contributors."""
        config = TrustedFilterConfig()
        assert config.allow_external is True

    def test_default_blocks_anonymous(self):
        """Default should block anonymous users."""
        config = TrustedFilterConfig()
        assert config.allow_anonymous is False

    def test_filter_content_types(self):
        """Should filter all content types by default."""
        config = TrustedFilterConfig()
        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is True

    def test_empty_allowlists_by_default(self):
        """Default should have empty allowlists and blocklists."""
        config = TrustedFilterConfig()
        assert config.allowed_users == []
        assert config.blocked_users == []
        assert config.allowed_domains == []
        assert config.blocked_domains == []

    def test_custom_allowlist(self):
        """Should accept custom allowlists."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob"],
            allowed_domains=["trusted.com"],
        )
        assert "alice" in config.allowed_users
        assert "bob" in config.allowed_users
        assert "trusted.com" in config.allowed_domains


class TestDataFilterConfig:
    """Tests for data filter configuration."""

    def test_default_mode_is_remove(self):
        """Default sanitization mode should be remove."""
        config = DataFilterConfig()
        assert config.mode == "remove"

    def test_default_aggressiveness_balanced(self):
        """Default aggressiveness should be balanced."""
        config = DataFilterConfig()
        assert config.aggressiveness == "balanced"

    def test_valid_aggressiveness_levels(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_default_removes_instructions(self):
        """Default should remove instructions."""
        config = DataFilterConfig()
        assert config.remove_instructions is True

    def test_default_preserves_code(self):
        """Default should preserve code blocks."""
        config = DataFilterConfig()
        assert config.remove_code_blocks is False

    def test_default_preserves_urls(self):
        """Default should preserve URLs."""
        config = DataFilterConfig()
        assert config.remove_urls is False

    def test_default_max_content_length(self):
        """Default max content length should be reasonable."""
        config = DataFilterConfig()
        assert config.max_content_length == 100000

    def test_custom_removal_patterns(self):
        """Should accept custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"REDACTED", r"SECRET:\s*\w+"]
        )
        assert len(config.custom_removal_patterns) == 2


class TestDetectorConfig:
    """Tests for detector configuration."""

    def test_default_confidence_threshold(self):
        """Default confidence threshold should be moderate."""
        config = DetectorConfig()
        assert config.confidence_threshold == 0.7

    def test_confidence_threshold_range(self):
        """Confidence threshold should accept valid range."""
        config = DetectorConfig(confidence_threshold=0.5)
        assert config.confidence_threshold == 0.5

        config = DetectorConfig(confidence_threshold=0.95)
        assert config.confidence_threshold == 0.95

    def test_default_min_risk_level(self):
        """Default minimum risk level should be LOW."""
        config = DetectorConfig()
        assert config.min_risk_level == RiskLevel.LOW

    def test_detector_components_enabled(self):
        """All detector components should be enabled by default."""
        config = DetectorConfig()
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_context_aware_enabled(self):
        """Context awareness should be enabled for indirect injection."""
        config = DetectorConfig()
        assert config.context_aware is True

    def test_tool_output_sensitivity(self):
        """Default tool output sensitivity should be elevated."""
        config = DetectorConfig()
        assert config.tool_output_sensitivity == 1.2

    def test_ml_model_settings(self):
        """ML model should have reasonable defaults."""
        config = DetectorConfig()
        assert config.ml_model_name == "microsoft/deberta-v3-base"
        assert config.ml_batch_size == 8
        assert config.ml_max_length == 512

    def test_false_positive_controls(self):
        """Should allow code instructions and documentation."""
        config = DetectorConfig()
        assert config.allow_code_instructions is True
        assert config.allow_documentation_examples is True

    def test_custom_patterns_empty_by_default(self):
        """Custom patterns should be empty by default."""
        config = DetectorConfig()
        assert config.custom_patterns == {}

    def test_custom_patterns_dict(self):
        """Should accept custom patterns as dict."""
        config = DetectorConfig(
            custom_patterns={
                "test_pattern": r"malicious\s+pattern",
            }
        )
        assert "test_pattern" in config.custom_patterns


class TestPromptFenceConfig:
    """Tests for prompt fence configuration."""

    def test_default_fence_format(self):
        """Default fence format should be XML."""
        config = PromptFenceConfig()
        assert config.fence_format == "xml"

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_signatures_enabled_by_default(self):
        """Cryptographic signatures should be enabled."""
        config = PromptFenceConfig()
        assert config.use_signatures is True

    def test_default_signature_algorithm(self):
        """Default signature algorithm should be HMAC-SHA256."""
        config = PromptFenceConfig()
        assert config.signature_algorithm == "hmac-sha256"

    def test_default_delimiters(self):
        """Should have clear trusted/untrusted delimiters."""
        config = PromptFenceConfig()
        assert "TRUSTED" in config.trusted_prefix
        assert "UNTRUSTED" in config.untrusted_prefix
        assert "END" in config.trusted_suffix

    def test_metadata_included_by_default(self):
        """Should include metadata by default."""
        config = PromptFenceConfig()
        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True

    def test_custom_delimiters(self):
        """Should accept custom delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="---SAFE---",
            trusted_suffix="---END_SAFE---",
        )
        assert config.trusted_prefix == "---SAFE---"
        assert config.trusted_suffix == "---END_SAFE---"


class TestLoggingConfig:
    """Tests for logging configuration."""

    def test_default_enabled(self):
        """Logging should be enabled by default."""
        config = LoggingConfig()
        assert config.enabled is True

    def test_default_log_level(self):
        """Default log level should be INFO."""
        config = LoggingConfig()
        assert config.log_level == "INFO"

    def test_logs_detections_by_default(self):
        """Should log detections by default."""
        config = LoggingConfig()
        assert config.log_detections is True

    def test_redacts_content_by_default(self):
        """Should redact content by default for security."""
        config = LoggingConfig()
        assert config.redact_content is True

    def test_max_logged_content_length(self):
        """Should limit logged content length."""
        config = LoggingConfig()
        assert config.max_logged_content_length == 200


class TestConfigValidation:
    """Tests for configuration validation and edge cases."""

    def test_zero_confidence_threshold_valid(self):
        """Confidence threshold of 0 should be valid (catches everything)."""
        config = DetectorConfig(confidence_threshold=0.0)
        assert config.confidence_threshold == 0.0

    def test_one_confidence_threshold_valid(self):
        """Confidence threshold of 1 should be valid (catches nothing)."""
        config = DetectorConfig(confidence_threshold=1.0)
        assert config.confidence_threshold == 1.0

    def test_very_low_confidence_threshold(self):
        """Very low confidence threshold should work."""
        config = DetectorConfig(confidence_threshold=0.1)
        assert config.confidence_threshold == 0.1

    def test_very_high_confidence_threshold(self):
        """Very high confidence threshold should work."""
        config = DetectorConfig(confidence_threshold=0.99)
        assert config.confidence_threshold == 0.99

    def test_zero_cache_ttl_valid(self):
        """Zero cache TTL should be valid (no caching)."""
        config = Config(cache_ttl_seconds=0)
        assert config.cache_ttl_seconds == 0

    def test_large_cache_ttl_valid(self):
        """Large cache TTL should be valid."""
        config = Config(cache_ttl_seconds=86400)
        assert config.cache_ttl_seconds == 86400

    def test_very_short_timeout_valid(self):
        """Very short timeout should be valid."""
        config = Config(request_timeout_seconds=0.1)
        assert config.request_timeout_seconds == 0.1

    def test_zero_max_concurrent_requests_edge_case(self):
        """Zero max concurrent requests should be valid edge case."""
        config = Config(max_concurrent_requests=0)
        assert config.max_concurrent_requests == 0


class TestConfigSerialization:
    """Tests for configuration serialization and deserialization."""

    def test_config_to_dict(self):
        """Config should serialize to dict."""
        config = Config.default()
        config_dict = config.model_dump()
        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict

    def test_config_from_dict(self):
        """Config should deserialize from dict."""
        config_dict = {
            "strict_mode": True,
            "fail_open": False,
        }
        config = Config(**config_dict)
        assert config.strict_mode is True
        assert config.fail_open is False

    def test_config_to_json_and_back(self):
        """Config should round-trip through JSON."""
        original = Config.strict()
        json_str = original.model_dump_json()
        config_dict = json.loads(json_str)
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.block_threshold == original.block_threshold

    def test_partial_config_update(self):
        """Should accept partial config updates."""
        config = Config(
            strict_mode=True,
            detector=DetectorConfig(confidence_threshold=0.6),
        )
        assert config.strict_mode is True
        assert config.detector.confidence_threshold == 0.6
        # Other fields should have defaults
        assert config.fail_open is False


class TestConfigInteractions:
    """Tests for interactions between config settings."""

    def test_strict_mode_with_fail_open_allowed(self):
        """Strict mode with fail_open=True should be allowed but illogical."""
        config = Config(strict_mode=True, fail_open=True)
        assert config.strict_mode is True
        assert config.fail_open is True

    def test_disabled_layers_in_config(self):
        """Should be able to disable individual layers."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
        )
        assert config.trusted_filter.enabled is False
        assert config.detector.enabled is False
        # Other layers still enabled
        assert config.data_filter.enabled is True

    def test_all_layers_disabled(self):
        """Should allow all layers to be disabled (passthrough mode)."""
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

    def test_high_sensitivity_with_low_threshold(self):
        """High sensitivity with low threshold should be valid."""
        config = Config(
            detector=DetectorConfig(
                confidence_threshold=0.3,
                tool_output_sensitivity=2.0,
            )
        )
        assert config.detector.confidence_threshold == 0.3
        assert config.detector.tool_output_sensitivity == 2.0


class TestPerformanceSettings:
    """Tests for performance-related configuration."""

    def test_default_caching_enabled(self):
        """Caching should be enabled by default."""
        config = Config.default()
        assert config.enable_caching is True

    def test_default_cache_ttl(self):
        """Cache TTL should be reasonable."""
        config = Config.default()
        assert config.cache_ttl_seconds == 3600

    def test_default_max_concurrent_requests(self):
        """Max concurrent requests should be reasonable."""
        config = Config.default()
        assert config.max_concurrent_requests == 100

    def test_default_request_timeout(self):
        """Request timeout should be reasonable."""
        config = Config.default()
        assert config.request_timeout_seconds == 30.0

    def test_custom_performance_settings(self):
        """Should accept custom performance settings."""
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
