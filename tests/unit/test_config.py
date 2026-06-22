"""
Unit tests for configuration validation and edge cases.

Tests the Config class and its validation logic, including edge cases
that could lead to security misconfigurations.
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
        """Default config should create without errors."""
        config = Config.default()

        assert config is not None
        assert config.trusted_filter.enabled
        assert config.data_filter.enabled
        assert config.detector.enabled
        assert config.prompt_fence.enabled

    def test_default_config_has_safe_thresholds(self):
        """Default config should have reasonable security thresholds."""
        config = Config.default()

        # Should not be too permissive
        assert config.detector.confidence_threshold >= 0.5
        assert config.block_threshold != RiskLevel.NONE

        # Should allow external contributors (OSS-friendly)
        assert config.trusted_filter.allow_external

    def test_default_fail_closed(self):
        """Default config should fail closed (secure by default)."""
        config = Config.default()

        assert not config.fail_open, "Should fail closed by default"


class TestConfigPresets:
    """Tests for configuration presets (strict, permissive)."""

    def test_strict_config_more_restrictive(self):
        """Strict config should be more restrictive than default."""
        default = Config.default()
        strict = Config.strict()

        # Lower confidence threshold = more aggressive detection
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Higher tool output sensitivity = more suspicious of tool outputs
        assert strict.detector.tool_output_sensitivity > default.detector.tool_output_sensitivity

        # Stricter trust requirements
        assert strict.trusted_filter.minimum_trust_level >= TrustLevel.DEVELOPER
        assert not strict.trusted_filter.allow_anonymous
        assert not strict.trusted_filter.allow_external

        # Lower block threshold = blocks more
        assert strict.block_threshold.value <= default.block_threshold.value

    def test_permissive_config_less_restrictive(self):
        """Permissive config should be less restrictive than default."""
        default = Config.default()
        permissive = Config.permissive()

        # Higher confidence threshold = less aggressive detection
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Allows anonymous and external users
        assert permissive.trusted_filter.allow_anonymous
        assert permissive.trusted_filter.allow_external

        # Higher block threshold = blocks less
        assert permissive.block_threshold.value >= default.block_threshold.value

        # Fails open (more availability over security)
        assert permissive.fail_open

    def test_strict_mode_flag(self):
        """Strict preset should have strict_mode enabled."""
        strict = Config.strict()

        assert strict.strict_mode
        assert not strict.fail_open

    def test_all_presets_create_successfully(self):
        """All preset configs should create without errors."""
        default = Config.default()
        strict = Config.strict()
        permissive = Config.permissive()

        assert default is not None
        assert strict is not None
        assert permissive is not None


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation."""

    def test_trust_level_validation(self):
        """Should accept valid trust levels."""
        config = TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)

        assert config.minimum_trust_level == TrustLevel.DEVELOPER

    def test_allowlist_blocklist(self):
        """Should support user allowlists and blocklists."""
        config = TrustedFilterConfig(
            allowed_users=["user1", "user2"],
            blocked_users=["attacker"],
        )

        assert "user1" in config.allowed_users
        assert "attacker" in config.blocked_users

    def test_domain_filtering(self):
        """Should support domain allowlists and blocklists."""
        config = TrustedFilterConfig(
            allowed_domains=["company.com"],
            blocked_domains=["evil.com"],
        )

        assert "company.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains

    def test_content_type_filtering_flags(self):
        """Should allow selective content type filtering."""
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

    def test_anonymous_external_consistency(self):
        """Anonymous requires external to be enabled."""
        # If anonymous is allowed, external must also be allowed
        config = TrustedFilterConfig(
            allow_anonymous=True,
            allow_external=True,
        )

        assert config.allow_anonymous
        assert config.allow_external


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_valid_sanitization_modes(self):
        """Should accept valid sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_valid_aggressiveness_levels(self):
        """Should accept valid aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_max_content_length_positive(self):
        """Max content length should be positive."""
        config = DataFilterConfig(max_content_length=50000)

        assert config.max_content_length > 0

    def test_custom_removal_patterns(self):
        """Should accept custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[r"REMOVE_THIS", r"SECRET:\w+"]
        )

        assert len(config.custom_removal_patterns) == 2

    def test_preservation_flags(self):
        """Should support preservation flags."""
        config = DataFilterConfig(
            preserve_code_context=True,
            preserve_documentation=True,
        )

        assert config.preserve_code_context
        assert config.preserve_documentation


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_confidence_threshold_range(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        for threshold in [0.0, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert 0.0 <= config.confidence_threshold <= 1.0

    def test_confidence_threshold_too_low_warning(self):
        """Very low confidence threshold should still be allowed but may cause false positives."""
        # Pydantic doesn't enforce range by default, but we test the value makes sense
        config = DetectorConfig(confidence_threshold=0.1)
        assert config.confidence_threshold == 0.1

    def test_confidence_threshold_too_high_warning(self):
        """Very high confidence threshold may miss attacks."""
        config = DetectorConfig(confidence_threshold=0.99)
        assert config.confidence_threshold == 0.99

    def test_detector_components_flags(self):
        """Should allow enabling/disabling detector components."""
        config = DetectorConfig(
            use_pattern_matching=True,
            use_ml_model=False,
            use_heuristics=True,
        )

        assert config.use_pattern_matching
        assert not config.use_ml_model
        assert config.use_heuristics

    def test_ml_model_settings(self):
        """Should accept ML model configuration."""
        config = DetectorConfig(
            ml_model_name="custom-model",
            ml_batch_size=16,
            ml_max_length=256,
        )

        assert config.ml_model_name == "custom-model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 256

    def test_tool_output_sensitivity_multiplier(self):
        """Tool output sensitivity should be >= 1.0."""
        config = DetectorConfig(tool_output_sensitivity=1.5)

        assert config.tool_output_sensitivity >= 1.0

    def test_context_awareness_flag(self):
        """Should allow toggling context awareness."""
        config = DetectorConfig(context_aware=True)

        assert config.context_aware

    def test_false_positive_control_flags(self):
        """Should support false positive reduction flags."""
        config = DetectorConfig(
            allow_code_instructions=True,
            allow_documentation_examples=True,
        )

        assert config.allow_code_instructions
        assert config.allow_documentation_examples

    def test_custom_patterns_dict(self):
        """Should accept custom patterns as dict."""
        config = DetectorConfig(
            custom_patterns={
                "custom_exfil": r"exfiltrate.*to.*evil\.com",
                "custom_backdoor": r"create.*backdoor.*account",
            }
        )

        assert "custom_exfil" in config.custom_patterns
        assert "custom_backdoor" in config.custom_patterns

    def test_blocked_patterns_list(self):
        """Should accept blocked patterns list."""
        config = DetectorConfig(
            blocked_patterns=["BLOCKED_PATTERN_1", "BLOCKED_PATTERN_2"]
        )

        assert len(config.blocked_patterns) == 2


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_valid_fence_formats(self):
        """Should accept valid fence formats."""
        for fmt in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_signature_settings(self):
        """Should support cryptographic signatures."""
        config = PromptFenceConfig(
            use_signatures=True,
            signature_algorithm="hmac-sha256",
        )

        assert config.use_signatures
        assert config.signature_algorithm == "hmac-sha256"

    def test_custom_fence_delimiters(self):
        """Should allow custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<TRUSTED>>>",
            trusted_suffix="<<<END_TRUSTED>>>",
            untrusted_prefix="<<<UNTRUSTED>>>",
            untrusted_suffix="<<<END_UNTRUSTED>>>",
        )

        assert config.trusted_prefix == "<<<TRUSTED>>>"
        assert config.trusted_suffix == "<<<END_TRUSTED>>>"

    def test_metadata_flags(self):
        """Should support metadata inclusion flags."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )

        assert config.include_metadata
        assert config.include_trust_level
        assert config.include_source_type


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_log_level_options(self):
        """Should accept standard log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_flags(self):
        """Should support granular logging flags."""
        config = LoggingConfig(
            log_detections=True,
            log_sanitizations=False,
            log_processing_times=True,
        )

        assert config.log_detections
        assert not config.log_sanitizations
        assert config.log_processing_times

    def test_content_redaction(self):
        """Should support content redaction in logs."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100,
        )

        assert config.redact_content
        assert config.max_logged_content_length == 100


class TestConfigEdgeCases:
    """Tests for configuration edge cases and validation."""

    def test_empty_config_uses_defaults(self):
        """Empty config should use default values."""
        config = Config()

        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None

    def test_partial_config_override(self):
        """Should allow partial config override."""
        config = Config(
            detector=DetectorConfig(confidence_threshold=0.5),
        )

        # Overridden
        assert config.detector.confidence_threshold == 0.5

        # Defaults preserved
        assert config.trusted_filter is not None
        assert config.data_filter is not None

    def test_all_layers_disabled(self):
        """Should allow disabling all layers (for testing)."""
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

    def test_risk_level_thresholds(self):
        """Should accept all valid risk level thresholds."""
        for level in [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM,
                      RiskLevel.HIGH, RiskLevel.CRITICAL]:
            config = Config(
                block_threshold=level,
                warn_threshold=level,
            )

            assert config.block_threshold == level
            assert config.warn_threshold == level

    def test_performance_settings(self):
        """Should accept performance tuning settings."""
        config = Config(
            enable_caching=True,
            cache_ttl_seconds=1800,
            max_concurrent_requests=50,
            request_timeout_seconds=15.0,
        )

        assert config.enable_caching
        assert config.cache_ttl_seconds == 1800
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 15.0

    def test_timeout_edge_cases(self):
        """Should handle timeout edge cases."""
        # Very short timeout
        config1 = Config(request_timeout_seconds=0.1)
        assert config1.request_timeout_seconds == 0.1

        # Very long timeout
        config2 = Config(request_timeout_seconds=300.0)
        assert config2.request_timeout_seconds == 300.0

    def test_cache_ttl_edge_cases(self):
        """Should handle cache TTL edge cases."""
        # Very short TTL
        config1 = Config(cache_ttl_seconds=1)
        assert config1.cache_ttl_seconds == 1

        # Very long TTL
        config2 = Config(cache_ttl_seconds=86400)  # 1 day
        assert config2.cache_ttl_seconds == 86400

    def test_concurrent_request_limits(self):
        """Should handle concurrent request limit edge cases."""
        # Low concurrency
        config1 = Config(max_concurrent_requests=1)
        assert config1.max_concurrent_requests == 1

        # High concurrency
        config2 = Config(max_concurrent_requests=1000)
        assert config2.max_concurrent_requests == 1000


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

    def test_config_from_dict(self):
        """Should create config from dict."""
        config_dict = {
            "strict_mode": True,
            "detector": {
                "confidence_threshold": 0.6,
            },
        }

        config = Config(**config_dict)

        assert config.strict_mode
        assert config.detector.confidence_threshold == 0.6

    def test_config_roundtrip(self):
        """Config should roundtrip through dict."""
        original = Config.strict()
        config_dict = original.model_dump()
        restored = Config(**config_dict)

        assert original.strict_mode == restored.strict_mode
        assert original.detector.confidence_threshold == restored.detector.confidence_threshold


class TestConfigSecurityImplications:
    """Tests to ensure configs don't create security vulnerabilities."""

    def test_default_not_fail_open(self):
        """Default should fail closed for security."""
        config = Config.default()

        assert not config.fail_open

    def test_strict_never_fails_open(self):
        """Strict mode should never fail open."""
        config = Config.strict()

        assert not config.fail_open

    def test_zero_confidence_threshold_warning(self):
        """Zero confidence threshold would accept everything - should still be allowed but dangerous."""
        config = DetectorConfig(confidence_threshold=0.0)

        # This is dangerous but allowed for testing/research
        assert config.confidence_threshold == 0.0

    def test_disabled_detector_still_has_other_layers(self):
        """If detector is disabled, other layers should still protect."""
        config = Config(
            detector=DetectorConfig(enabled=False),
        )

        # Defense in depth - other layers still active
        assert config.trusted_filter.enabled
        assert config.data_filter.enabled

    def test_permissive_still_has_detection(self):
        """Even permissive mode should still detect attacks."""
        config = Config.permissive()

        # Still detects, just with higher threshold
        assert config.detector.enabled
        assert config.detector.confidence_threshold > 0.0
