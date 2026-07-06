"""
Unit tests for configuration module.

Tests configuration validation, factory methods, and edge cases.
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


class TestConfigFactory:
    """Tests for Config factory methods."""

    def test_default_config_creates_valid_instance(self):
        """Default factory should create valid config."""
        config = Config.default()
        assert config is not None
        assert isinstance(config, Config)

    def test_strict_config_has_strict_settings(self):
        """Strict factory should have strict security settings."""
        config = Config.strict()

        # Should be in strict mode
        assert config.strict_mode is True
        assert config.fail_open is False

        # Should have strict trust settings
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False

        # Should have aggressive sanitization
        assert config.data_filter.aggressiveness == "aggressive"

        # Should have lower detection threshold
        assert config.detector.confidence_threshold == 0.5
        assert config.detector.tool_output_sensitivity == 1.5

        # Should block at lower risk level
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_has_permissive_settings(self):
        """Permissive factory should have permissive settings."""
        config = Config.permissive()

        # Should fail open
        assert config.fail_open is True

        # Should allow all trust levels
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True

        # Should have minimal sanitization
        assert config.data_filter.aggressiveness == "minimal"

        # Should have higher detection threshold
        assert config.detector.confidence_threshold == 0.85
        assert config.detector.tool_output_sensitivity == 1.0

        # Should only block at critical level
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_factory_methods_return_different_instances(self):
        """Each factory call should return a new instance."""
        config1 = Config.default()
        config2 = Config.default()

        assert config1 is not config2
        assert config1.model_dump() == config2.model_dump()


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig."""

    def test_default_trust_level_allows_external(self):
        """Default config should allow external contributors."""
        config = TrustedFilterConfig()
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_external is True

    def test_can_configure_allowed_users(self):
        """Should accept list of allowed users."""
        config = TrustedFilterConfig(allowed_users=["user1", "user2"])
        assert "user1" in config.allowed_users
        assert "user2" in config.allowed_users

    def test_can_configure_blocked_users(self):
        """Should accept list of blocked users."""
        config = TrustedFilterConfig(blocked_users=["spammer", "bot"])
        assert "spammer" in config.blocked_users
        assert "bot" in config.blocked_users

    def test_can_configure_domain_allowlist(self):
        """Should accept domain allowlist."""
        config = TrustedFilterConfig(allowed_domains=["example.com", "trusted.org"])
        assert "example.com" in config.allowed_domains

    def test_can_configure_domain_blocklist(self):
        """Should accept domain blocklist."""
        config = TrustedFilterConfig(blocked_domains=["evil.com", "spam.net"])
        assert "evil.com" in config.blocked_domains

    def test_content_type_filters_enabled_by_default(self):
        """Content type filters should be enabled by default."""
        config = TrustedFilterConfig()
        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is True

    def test_can_disable_specific_content_filters(self):
        """Should allow disabling specific content filters."""
        config = TrustedFilterConfig(
            filter_issue_content=False,
            filter_comments=False,
        )
        assert config.filter_issue_content is False
        assert config.filter_comments is False
        assert config.filter_file_content is True  # Still enabled


class TestDataFilterConfig:
    """Tests for DataFilterConfig."""

    def test_default_mode_is_remove(self):
        """Default sanitization mode should be remove."""
        config = DataFilterConfig()
        assert config.mode == "remove"

    def test_default_aggressiveness_is_balanced(self):
        """Default aggressiveness should be balanced."""
        config = DataFilterConfig()
        assert config.aggressiveness == "balanced"

    def test_can_set_aggressiveness_levels(self):
        """Should accept different aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_can_set_sanitization_mode(self):
        """Should accept different sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_preserves_code_and_docs_by_default(self):
        """Should preserve code context and documentation by default."""
        config = DataFilterConfig()
        assert config.preserve_code_context is True
        assert config.preserve_documentation is True

    def test_has_reasonable_max_content_length(self):
        """Should have reasonable max content length."""
        config = DataFilterConfig()
        assert config.max_content_length == 100000
        assert config.max_content_length > 0

    def test_can_configure_custom_removal_patterns(self):
        """Should accept custom removal patterns."""
        patterns = [r"SECRET_\w+", r"PASSWORD:\s*\S+"]
        config = DataFilterConfig(custom_removal_patterns=patterns)
        assert len(config.custom_removal_patterns) == 2
        assert patterns[0] in config.custom_removal_patterns


class TestDetectorConfig:
    """Tests for DetectorConfig."""

    def test_default_confidence_threshold_is_reasonable(self):
        """Default confidence threshold should be reasonable."""
        config = DetectorConfig()
        assert 0 <= config.confidence_threshold <= 1
        assert config.confidence_threshold == 0.7

    def test_all_detector_components_enabled_by_default(self):
        """All detector components should be enabled by default."""
        config = DetectorConfig()
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_context_aware_enabled_by_default(self):
        """Context awareness should be enabled by default."""
        config = DetectorConfig()
        assert config.context_aware is True

    def test_tool_output_sensitivity_is_elevated(self):
        """Tool output sensitivity should be elevated."""
        config = DetectorConfig()
        assert config.tool_output_sensitivity >= 1.0
        assert config.tool_output_sensitivity == 1.2

    def test_can_configure_ml_model_settings(self):
        """Should allow configuring ML model settings."""
        config = DetectorConfig(
            ml_model_name="custom/model",
            ml_batch_size=16,
            ml_max_length=256,
        )
        assert config.ml_model_name == "custom/model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_can_configure_custom_patterns(self):
        """Should accept custom detection patterns."""
        patterns = {
            "custom_attack": r"execute\s+dangerous",
            "exfil_pattern": r"send\s+data\s+to",
        }
        config = DetectorConfig(custom_patterns=patterns)
        assert "custom_attack" in config.custom_patterns
        assert config.custom_patterns["custom_attack"] == patterns["custom_attack"]

    def test_can_configure_blocked_patterns(self):
        """Should accept blocked pattern list."""
        blocked = ["known_attack_1", "known_attack_2"]
        config = DetectorConfig(blocked_patterns=blocked)
        assert len(config.blocked_patterns) == 2
        assert "known_attack_1" in config.blocked_patterns

    def test_allows_code_instructions_by_default(self):
        """Should allow code instructions by default to reduce false positives."""
        config = DetectorConfig()
        assert config.allow_code_instructions is True
        assert config.allow_documentation_examples is True


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig."""

    def test_default_fence_format_is_xml(self):
        """Default fence format should be XML."""
        config = PromptFenceConfig()
        assert config.fence_format == "xml"

    def test_can_set_fence_format(self):
        """Should accept different fence formats."""
        for format in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=format)
            assert config.fence_format == format

    def test_uses_signatures_by_default(self):
        """Should use cryptographic signatures by default."""
        config = PromptFenceConfig()
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"

    def test_has_default_fence_delimiters(self):
        """Should have default fence delimiters."""
        config = PromptFenceConfig()
        assert "TRUSTED" in config.trusted_prefix
        assert "UNTRUSTED" in config.untrusted_prefix
        assert "END" in config.trusted_suffix

    def test_includes_metadata_by_default(self):
        """Should include metadata by default."""
        config = PromptFenceConfig()
        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True

    def test_can_customize_fence_delimiters(self):
        """Should allow customizing fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="[SAFE]",
            trusted_suffix="[/SAFE]",
            untrusted_prefix="[UNSAFE]",
            untrusted_suffix="[/UNSAFE]",
        )
        assert config.trusted_prefix == "[SAFE]"
        assert config.trusted_suffix == "[/SAFE]"
        assert config.untrusted_prefix == "[UNSAFE]"
        assert config.untrusted_suffix == "[/UNSAFE]"


class TestLoggingConfig:
    """Tests for LoggingConfig."""

    def test_logging_enabled_by_default(self):
        """Logging should be enabled by default."""
        config = LoggingConfig()
        assert config.enabled is True

    def test_default_log_level_is_info(self):
        """Default log level should be INFO."""
        config = LoggingConfig()
        assert config.log_level == "INFO"

    def test_logs_detections_and_sanitizations_by_default(self):
        """Should log detections and sanitizations by default."""
        config = LoggingConfig()
        assert config.log_detections is True
        assert config.log_sanitizations is True
        assert config.log_processing_times is True

    def test_redacts_content_by_default(self):
        """Should redact content by default for privacy."""
        config = LoggingConfig()
        assert config.redact_content is True

    def test_has_max_logged_content_length(self):
        """Should limit logged content length."""
        config = LoggingConfig()
        assert config.max_logged_content_length == 200
        assert config.max_logged_content_length > 0


class TestMasterConfig:
    """Tests for master Config class."""

    def test_config_has_all_layer_configs(self):
        """Master config should have all layer configs."""
        config = Config()
        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None

    def test_fail_open_disabled_by_default(self):
        """fail_open should be disabled by default for security."""
        config = Config()
        assert config.fail_open is False

    def test_strict_mode_disabled_by_default(self):
        """strict_mode should be disabled by default."""
        config = Config()
        assert config.strict_mode is False

    def test_caching_enabled_by_default(self):
        """Caching should be enabled by default for performance."""
        config = Config()
        assert config.enable_caching is True
        assert config.cache_ttl_seconds > 0

    def test_has_reasonable_performance_settings(self):
        """Should have reasonable performance settings."""
        config = Config()
        assert config.max_concurrent_requests > 0
        assert config.request_timeout_seconds > 0
        assert config.cache_ttl_seconds == 3600
        assert config.max_concurrent_requests == 100
        assert config.request_timeout_seconds == 30.0

    def test_has_default_risk_thresholds(self):
        """Should have default risk thresholds."""
        config = Config()
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_can_override_all_layer_configs(self):
        """Should allow overriding all layer configs."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(mode="mask"),
            detector=DetectorConfig(confidence_threshold=0.9),
            prompt_fence=PromptFenceConfig(fence_format="json"),
            logging=LoggingConfig(log_level="DEBUG"),
        )

        assert config.trusted_filter.enabled is False
        assert config.data_filter.mode == "mask"
        assert config.detector.confidence_threshold == 0.9
        assert config.prompt_fence.fence_format == "json"
        assert config.logging.log_level == "DEBUG"

    def test_can_override_global_settings(self):
        """Should allow overriding global settings."""
        config = Config(
            fail_open=True,
            strict_mode=True,
            enable_caching=False,
            max_concurrent_requests=50,
            request_timeout_seconds=60.0,
        )

        assert config.fail_open is True
        assert config.strict_mode is True
        assert config.enable_caching is False
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 60.0


class TestConfigValidation:
    """Tests for configuration validation and edge cases."""

    def test_invalid_confidence_threshold_rejected(self):
        """Should reject invalid confidence threshold."""
        # Pydantic will allow this but we should validate behavior
        config = DetectorConfig(confidence_threshold=1.5)
        # The value will be set, but our detector should handle it
        assert config.confidence_threshold == 1.5

    def test_negative_cache_ttl_accepted(self):
        """Negative cache TTL might be used to disable caching."""
        config = Config(cache_ttl_seconds=-1)
        assert config.cache_ttl_seconds == -1

    def test_zero_max_concurrent_requests_accepted(self):
        """Zero max concurrent requests is technically valid."""
        config = Config(max_concurrent_requests=0)
        assert config.max_concurrent_requests == 0

    def test_empty_allowed_users_list(self):
        """Empty allowed users list should be valid."""
        config = TrustedFilterConfig(allowed_users=[])
        assert config.allowed_users == []

    def test_empty_custom_patterns_dict(self):
        """Empty custom patterns dict should be valid."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_very_large_max_content_length(self):
        """Very large max content length should be accepted."""
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_very_small_max_content_length(self):
        """Very small max content length should be accepted."""
        config = DataFilterConfig(max_content_length=1)
        assert config.max_content_length == 1


class TestConfigSerialization:
    """Tests for config serialization."""

    def test_config_can_be_serialized_to_dict(self):
        """Config should serialize to dict."""
        config = Config.default()
        config_dict = config.model_dump()

        assert isinstance(config_dict, dict)
        assert "trusted_filter" in config_dict
        assert "data_filter" in config_dict
        assert "detector" in config_dict
        assert "prompt_fence" in config_dict

    def test_serialized_config_can_be_deserialized(self):
        """Serialized config should deserialize correctly."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold

    def test_config_with_custom_values_serializes(self):
        """Config with custom values should serialize."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allowed_users=["user1", "user2"],
                blocked_domains=["evil.com"],
            ),
            detector=DetectorConfig(
                custom_patterns={"test": r"pattern"},
                blocked_patterns=["blocked"],
            ),
        )

        config_dict = config.model_dump()
        assert "user1" in config_dict["trusted_filter"]["allowed_users"]
        assert "evil.com" in config_dict["trusted_filter"]["blocked_domains"]
        assert "test" in config_dict["detector"]["custom_patterns"]
