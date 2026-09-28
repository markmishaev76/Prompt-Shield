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


class TestConfigFactoryMethods:
    """Tests for Config factory methods."""

    def test_default_config_creates_valid_instance(self):
        """Default config should create valid configuration."""
        config = Config.default()

        assert config is not None
        assert isinstance(config, Config)
        assert config.trusted_filter.enabled is True
        assert config.data_filter.enabled is True
        assert config.detector.enabled is True
        assert config.prompt_fence.enabled is True

    def test_default_config_has_balanced_settings(self):
        """Default config should have balanced security settings."""
        config = Config.default()

        # Should allow external contributors (OSS friendly)
        assert config.trusted_filter.allow_external is True
        assert config.trusted_filter.minimum_trust_level == TrustLevel.EXTERNAL

        # Balanced detection thresholds
        assert config.detector.confidence_threshold == 0.7
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM

        # Not too strict
        assert config.strict_mode is False
        assert config.fail_open is False

    def test_strict_config_has_high_security_settings(self):
        """Strict config should have aggressive security settings."""
        config = Config.strict()

        assert config.strict_mode is True
        assert config.fail_open is False

        # Restrictive trust settings
        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.trusted_filter.allow_anonymous is False
        assert config.trusted_filter.allow_external is False

        # Lower confidence threshold (more sensitive)
        assert config.detector.confidence_threshold == 0.5
        assert config.detector.tool_output_sensitivity == 1.5

        # Aggressive filtering
        assert config.data_filter.aggressiveness == "aggressive"

        # Lower block threshold (blocks more)
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_permissive_config_has_low_security_settings(self):
        """Permissive config should be tolerant of false positives."""
        config = Config.permissive()

        assert config.fail_open is True

        # Permissive trust settings
        assert config.trusted_filter.allow_anonymous is True
        assert config.trusted_filter.allow_external is True

        # Higher confidence threshold (less sensitive)
        assert config.detector.confidence_threshold == 0.85
        assert config.detector.tool_output_sensitivity == 1.0

        # Minimal filtering
        assert config.data_filter.aggressiveness == "minimal"

        # Higher block threshold (blocks less)
        assert config.block_threshold == RiskLevel.CRITICAL

    def test_factory_configs_are_independent(self):
        """Factory methods should create independent instances."""
        default = Config.default()
        strict = Config.strict()
        permissive = Config.permissive()

        # Modify one config
        default.strict_mode = True

        # Others should be unchanged
        assert strict.strict_mode is True
        assert permissive.strict_mode is False


class TestTrustedFilterConfig:
    """Tests for TrustedFilterConfig validation."""

    def test_default_trusted_filter_allows_external(self):
        """Default trusted filter should allow external contributors."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.allow_external is True
        assert config.allow_anonymous is False
        assert config.minimum_trust_level == TrustLevel.EXTERNAL

    def test_trusted_filter_with_allowed_users(self):
        """Should support user allowlists."""
        config = TrustedFilterConfig(
            allowed_users=["alice", "bob", "charlie"]
        )

        assert len(config.allowed_users) == 3
        assert "alice" in config.allowed_users

    def test_trusted_filter_with_blocked_users(self):
        """Should support user blocklists."""
        config = TrustedFilterConfig(
            blocked_users=["attacker@evil.com", "malicious_user"]
        )

        assert len(config.blocked_users) == 2
        assert "attacker@evil.com" in config.blocked_users

    def test_trusted_filter_with_domain_filters(self):
        """Should support domain allowlists and blocklists."""
        config = TrustedFilterConfig(
            allowed_domains=["trusted.com", "safe.org"],
            blocked_domains=["evil.com", "malicious.net"]
        )

        assert len(config.allowed_domains) == 2
        assert len(config.blocked_domains) == 2
        assert "trusted.com" in config.allowed_domains
        assert "evil.com" in config.blocked_domains

    def test_trusted_filter_content_type_settings(self):
        """Should configure which content types to filter."""
        config = TrustedFilterConfig(
            filter_issue_content=True,
            filter_comments=True,
            filter_file_content=False,
            filter_wiki_pages=False
        )

        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is False
        assert config.filter_wiki_pages is False


class TestDataFilterConfig:
    """Tests for DataFilterConfig validation."""

    def test_default_data_filter_balanced(self):
        """Default data filter should use balanced mode."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"

    def test_data_filter_sanitization_modes(self):
        """Should support different sanitization modes."""
        for mode in ["remove", "mask", "escape", "tag"]:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_data_filter_aggressiveness_levels(self):
        """Should support different aggressiveness levels."""
        for level in ["minimal", "balanced", "aggressive"]:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_data_filter_removal_options(self):
        """Should configure what content to remove."""
        config = DataFilterConfig(
            remove_instructions=True,
            remove_code_blocks=True,
            remove_urls=True,
            remove_email_addresses=True
        )

        assert config.remove_instructions is True
        assert config.remove_code_blocks is True
        assert config.remove_urls is True
        assert config.remove_email_addresses is True

    def test_data_filter_preservation_settings(self):
        """Should configure content preservation."""
        config = DataFilterConfig(
            preserve_code_context=False,
            preserve_documentation=False
        )

        assert config.preserve_code_context is False
        assert config.preserve_documentation is False

    def test_data_filter_max_content_length(self):
        """Should enforce max content length."""
        config = DataFilterConfig(max_content_length=50000)

        assert config.max_content_length == 50000

    def test_data_filter_custom_patterns(self):
        """Should support custom removal patterns."""
        config = DataFilterConfig(
            custom_removal_patterns=[
                r"REMOVE_THIS",
                r"SECRET_.*",
            ]
        )

        assert len(config.custom_removal_patterns) == 2
        assert r"SECRET_.*" in config.custom_removal_patterns


class TestDetectorConfig:
    """Tests for DetectorConfig validation."""

    def test_default_detector_config(self):
        """Default detector should enable all components."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.use_heuristics is True

    def test_detector_confidence_threshold_validation(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        for threshold in [0.0, 0.5, 0.7, 0.9, 1.0]:
            config = DetectorConfig(confidence_threshold=threshold)
            assert config.confidence_threshold == threshold

    def test_detector_risk_level_thresholds(self):
        """Should configure minimum risk level."""
        for risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            config = DetectorConfig(min_risk_level=risk_level)
            assert config.min_risk_level == risk_level

    def test_detector_ml_model_settings(self):
        """Should configure ML model parameters."""
        config = DetectorConfig(
            ml_model_name="custom-model",
            ml_batch_size=16,
            ml_max_length=1024
        )

        assert config.ml_model_name == "custom-model"
        assert config.ml_batch_size == 16
        assert config.ml_max_length == 1024

    def test_detector_context_awareness(self):
        """Should configure context awareness settings."""
        config = DetectorConfig(
            context_aware=True,
            tool_output_sensitivity=1.5
        )

        assert config.context_aware is True
        assert config.tool_output_sensitivity == 1.5

    def test_detector_false_positive_controls(self):
        """Should configure false positive reduction."""
        config = DetectorConfig(
            allow_code_instructions=False,
            allow_documentation_examples=False
        )

        assert config.allow_code_instructions is False
        assert config.allow_documentation_examples is False

    def test_detector_custom_patterns(self):
        """Should support custom detection patterns."""
        config = DetectorConfig(
            custom_patterns={
                "custom_attack": r"malicious.*pattern",
                "another_attack": r"evil.*code"
            }
        )

        assert len(config.custom_patterns) == 2
        assert "custom_attack" in config.custom_patterns

    def test_detector_pattern_blocklist(self):
        """Should support pattern blocklist."""
        config = DetectorConfig(
            blocked_patterns=["pattern1", "pattern2", "pattern3"]
        )

        assert len(config.blocked_patterns) == 3
        assert "pattern2" in config.blocked_patterns


class TestPromptFenceConfig:
    """Tests for PromptFenceConfig validation."""

    def test_default_prompt_fence_config(self):
        """Default prompt fence should use XML format with signatures."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True
        assert config.signature_algorithm == "hmac-sha256"

    def test_prompt_fence_formats(self):
        """Should support different fence formats."""
        for format in ["xml", "markdown", "json", "delimiter"]:
            config = PromptFenceConfig(fence_format=format)
            assert config.fence_format == format

    def test_prompt_fence_custom_delimiters(self):
        """Should support custom fence delimiters."""
        config = PromptFenceConfig(
            trusted_prefix="<<<SAFE>>>",
            trusted_suffix="<<<END_SAFE>>>",
            untrusted_prefix="<<<UNSAFE>>>",
            untrusted_suffix="<<<END_UNSAFE>>>"
        )

        assert config.trusted_prefix == "<<<SAFE>>>"
        assert config.trusted_suffix == "<<<END_SAFE>>>"
        assert config.untrusted_prefix == "<<<UNSAFE>>>"
        assert config.untrusted_suffix == "<<<END_UNSAFE>>>"

    def test_prompt_fence_metadata_settings(self):
        """Should configure metadata inclusion."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True
        )

        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True

    def test_prompt_fence_signature_algorithms(self):
        """Should support different signature algorithms."""
        for algo in ["hmac-sha256", "hmac-sha512"]:
            config = PromptFenceConfig(signature_algorithm=algo)
            assert config.signature_algorithm == algo


class TestLoggingConfig:
    """Tests for LoggingConfig validation."""

    def test_default_logging_config(self):
        """Default logging should be enabled with INFO level."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.log_detections is True
        assert config.log_sanitizations is True

    def test_logging_levels(self):
        """Should support different log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            config = LoggingConfig(log_level=level)
            assert config.log_level == level

    def test_logging_selective_events(self):
        """Should configure which events to log."""
        config = LoggingConfig(
            log_detections=False,
            log_sanitizations=False,
            log_processing_times=False
        )

        assert config.log_detections is False
        assert config.log_sanitizations is False
        assert config.log_processing_times is False

    def test_logging_content_redaction(self):
        """Should configure content redaction."""
        config = LoggingConfig(
            redact_content=True,
            max_logged_content_length=100
        )

        assert config.redact_content is True
        assert config.max_logged_content_length == 100


class TestConfigValidation:
    """Tests for Config class validation and edge cases."""

    def test_config_with_all_layers_disabled(self):
        """Should allow creating config with all layers disabled."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=False),
            prompt_fence=PromptFenceConfig(enabled=False)
        )

        assert config.trusted_filter.enabled is False
        assert config.data_filter.enabled is False
        assert config.detector.enabled is False
        assert config.prompt_fence.enabled is False

    def test_config_fail_open_mode(self):
        """Should support fail-open mode for resilience."""
        config = Config(fail_open=True)

        assert config.fail_open is True

    def test_config_strict_mode(self):
        """Should support strict mode for security."""
        config = Config(strict_mode=True)

        assert config.strict_mode is True

    def test_config_performance_settings(self):
        """Should configure performance parameters."""
        config = Config(
            enable_caching=False,
            cache_ttl_seconds=7200,
            max_concurrent_requests=50,
            request_timeout_seconds=60.0
        )

        assert config.enable_caching is False
        assert config.cache_ttl_seconds == 7200
        assert config.max_concurrent_requests == 50
        assert config.request_timeout_seconds == 60.0

    def test_config_risk_thresholds(self):
        """Should configure risk thresholds."""
        config = Config(
            block_threshold=RiskLevel.MEDIUM,
            warn_threshold=RiskLevel.LOW
        )

        assert config.block_threshold == RiskLevel.MEDIUM
        assert config.warn_threshold == RiskLevel.LOW

    def test_config_nested_layer_configs(self):
        """Should properly nest layer configurations."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.DEVELOPER
            ),
            detector=DetectorConfig(
                confidence_threshold=0.8
            )
        )

        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.detector.confidence_threshold == 0.8


class TestConfigEdgeCases:
    """Tests for configuration edge cases and boundary conditions."""

    def test_detector_zero_confidence_threshold(self):
        """Should allow zero confidence threshold (detect everything)."""
        config = DetectorConfig(confidence_threshold=0.0)

        assert config.confidence_threshold == 0.0

    def test_detector_max_confidence_threshold(self):
        """Should allow max confidence threshold (detect nothing)."""
        config = DetectorConfig(confidence_threshold=1.0)

        assert config.confidence_threshold == 1.0

    def test_data_filter_zero_max_length(self):
        """Should handle zero max content length."""
        config = DataFilterConfig(max_content_length=0)

        assert config.max_content_length == 0

    def test_data_filter_very_large_max_length(self):
        """Should handle very large max content length."""
        config = DataFilterConfig(max_content_length=10_000_000)

        assert config.max_content_length == 10_000_000

    def test_config_zero_cache_ttl(self):
        """Should allow zero cache TTL (no caching)."""
        config = Config(cache_ttl_seconds=0)

        assert config.cache_ttl_seconds == 0

    def test_config_zero_timeout(self):
        """Should allow zero timeout (no timeout)."""
        config = Config(request_timeout_seconds=0.0)

        assert config.request_timeout_seconds == 0.0

    def test_logging_zero_max_content_length(self):
        """Should allow zero max logged content (no content logged)."""
        config = LoggingConfig(max_logged_content_length=0)

        assert config.max_logged_content_length == 0

    def test_empty_allowlists_and_blocklists(self):
        """Should handle empty allowlists and blocklists."""
        config = TrustedFilterConfig(
            allowed_users=[],
            blocked_users=[],
            allowed_domains=[],
            blocked_domains=[]
        )

        assert len(config.allowed_users) == 0
        assert len(config.blocked_users) == 0
        assert len(config.allowed_domains) == 0
        assert len(config.blocked_domains) == 0

    def test_empty_custom_patterns(self):
        """Should handle empty custom patterns."""
        config = DetectorConfig(
            custom_patterns={},
            blocked_patterns=[]
        )

        assert len(config.custom_patterns) == 0
        assert len(config.blocked_patterns) == 0
