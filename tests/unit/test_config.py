"""
Unit tests for the Config class and configuration system.

Tests configuration presets, validation, edge cases, and interactions.
"""

import pytest

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

    def test_config_default_initialization(self):
        """Config should initialize with default values."""
        config = Config()

        assert config.trusted_filter is not None
        assert config.data_filter is not None
        assert config.detector is not None
        assert config.prompt_fence is not None
        assert config.logging is not None

    def test_config_default_method(self):
        """Config.default() should return default configuration."""
        config = Config.default()

        assert config.fail_open is False
        assert config.strict_mode is False
        assert config.enable_caching is True
        assert config.block_threshold == RiskLevel.HIGH
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_trusted_filter_defaults(self):
        """TrustedFilterConfig should have correct defaults."""
        config = TrustedFilterConfig()

        assert config.enabled is True
        assert config.minimum_trust_level == TrustLevel.EXTERNAL
        assert config.allow_anonymous is False
        assert config.allow_external is True
        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True

    def test_data_filter_defaults(self):
        """DataFilterConfig should have correct defaults."""
        config = DataFilterConfig()

        assert config.enabled is True
        assert config.mode == "remove"
        assert config.aggressiveness == "balanced"
        assert config.remove_instructions is True
        assert config.preserve_code_context is True
        assert config.max_content_length == 100000

    def test_detector_defaults(self):
        """DetectorConfig should have correct defaults."""
        config = DetectorConfig()

        assert config.enabled is True
        assert config.confidence_threshold == 0.7
        assert config.min_risk_level == RiskLevel.LOW
        assert config.use_pattern_matching is True
        assert config.use_ml_model is True
        assert config.context_aware is True
        assert config.tool_output_sensitivity == 1.2

    def test_prompt_fence_defaults(self):
        """PromptFenceConfig should have correct defaults."""
        config = PromptFenceConfig()

        assert config.enabled is True
        assert config.fence_format == "xml"
        assert config.use_signatures is True
        assert config.include_metadata is True


class TestConfigPresets:
    """Tests for configuration presets (strict, permissive)."""

    def test_strict_config_more_restrictive(self):
        """Strict config should be more restrictive than default."""
        default = Config.default()
        strict = Config.strict()

        # Strict should require higher trust level
        assert strict.trusted_filter.minimum_trust_level > default.trusted_filter.minimum_trust_level
        # Strict should not allow anonymous or external
        assert strict.trusted_filter.allow_anonymous is False
        assert strict.trusted_filter.allow_external is False
        # Strict should have lower confidence threshold (catches more)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold
        # Strict should block at lower risk level
        assert strict.block_threshold < default.block_threshold

    def test_permissive_config_more_lenient(self):
        """Permissive config should be more lenient than default."""
        default = Config.default()
        permissive = Config.permissive()

        # Permissive should allow anonymous and external
        assert permissive.trusted_filter.allow_anonymous is True
        assert permissive.trusted_filter.allow_external is True
        # Permissive should have higher confidence threshold (catches less)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold
        # Permissive should fail open
        assert permissive.fail_open is True
        # Permissive should only block critical threats
        assert permissive.block_threshold == RiskLevel.CRITICAL

    def test_strict_mode_flag(self):
        """Strict config should set strict_mode flag."""
        strict = Config.strict()
        assert strict.strict_mode is True

    def test_permissive_fail_open(self):
        """Permissive config should fail open."""
        permissive = Config.permissive()
        assert permissive.fail_open is True


class TestConfigValidation:
    """Tests for configuration validation and edge cases."""

    def test_confidence_threshold_bounds(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        config1 = DetectorConfig(confidence_threshold=0.0)
        assert config1.confidence_threshold == 0.0

        config2 = DetectorConfig(confidence_threshold=1.0)
        assert config2.confidence_threshold == 1.0

        config3 = DetectorConfig(confidence_threshold=0.5)
        assert config3.confidence_threshold == 0.5

    def test_negative_timeout_invalid(self):
        """Negative timeout should be rejected."""
        with pytest.raises((ValueError, Exception)):
            Config(request_timeout_seconds=-1.0)

    def test_negative_cache_ttl_invalid(self):
        """Negative cache TTL should be rejected."""
        with pytest.raises((ValueError, Exception)):
            Config(cache_ttl_seconds=-1)

    def test_zero_max_concurrent_requests(self):
        """Zero max concurrent requests should be allowed (unlimited)."""
        # Some systems use 0 to mean unlimited
        config = Config(max_concurrent_requests=0)
        assert config.max_concurrent_requests == 0

    def test_very_large_content_length(self):
        """Very large content length should be allowed."""
        config = DataFilterConfig(max_content_length=10_000_000)
        assert config.max_content_length == 10_000_000

    def test_empty_custom_patterns(self):
        """Empty custom patterns should be allowed."""
        config = DetectorConfig(custom_patterns={})
        assert config.custom_patterns == {}

    def test_empty_allowlists(self):
        """Empty allowlists should be allowed."""
        config = TrustedFilterConfig(
            allowed_users=[],
            allowed_domains=[],
        )
        assert config.allowed_users == []
        assert config.allowed_domains == []


class TestConfigCombinations:
    """Tests for configuration combinations and interactions."""

    def test_all_layers_disabled(self):
        """All layers can be disabled."""
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

    def test_only_detector_enabled(self):
        """Only detector can be enabled with others disabled."""
        config = Config(
            trusted_filter=TrustedFilterConfig(enabled=False),
            data_filter=DataFilterConfig(enabled=False),
            detector=DetectorConfig(enabled=True),
            prompt_fence=PromptFenceConfig(enabled=False),
        )

        assert config.trusted_filter.enabled is False
        assert config.detector.enabled is True

    def test_strict_trust_with_permissive_detection(self):
        """Can mix strict trust filtering with permissive detection."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.DEVELOPER,
                allow_external=False,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.9,  # High threshold = permissive
            ),
        )

        assert config.trusted_filter.minimum_trust_level == TrustLevel.DEVELOPER
        assert config.detector.confidence_threshold == 0.9

    def test_aggressive_sanitization_with_high_detection_threshold(self):
        """Can combine aggressive sanitization with high detection threshold."""
        config = Config(
            data_filter=DataFilterConfig(
                aggressiveness="aggressive",
                remove_instructions=True,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.9,
            ),
        )

        assert config.data_filter.aggressiveness == "aggressive"
        assert config.detector.confidence_threshold == 0.9


class TestLoggingConfig:
    """Tests for logging configuration."""

    def test_logging_defaults(self):
        """LoggingConfig should have correct defaults."""
        config = LoggingConfig()

        assert config.enabled is True
        assert config.log_level == "INFO"
        assert config.log_detections is True
        assert config.log_sanitizations is True
        assert config.redact_content is True

    def test_logging_can_be_disabled(self):
        """Logging can be disabled."""
        config = LoggingConfig(enabled=False)
        assert config.enabled is False

    def test_logging_redaction_configurable(self):
        """Content redaction can be configured."""
        config = LoggingConfig(redact_content=False)
        assert config.redact_content is False

    def test_max_logged_content_length(self):
        """Max logged content length is configurable."""
        config = LoggingConfig(max_logged_content_length=500)
        assert config.max_logged_content_length == 500


class TestCustomPatterns:
    """Tests for custom pattern configuration."""

    def test_add_custom_detection_patterns(self):
        """Custom detection patterns can be added."""
        custom_patterns = {
            "custom_attack": r"very\s+specific\s+attack",
            "another_pattern": r"dangerous\s+instruction",
        }
        config = DetectorConfig(custom_patterns=custom_patterns)

        assert "custom_attack" in config.custom_patterns
        assert "another_pattern" in config.custom_patterns

    def test_add_custom_removal_patterns(self):
        """Custom removal patterns can be added."""
        custom_removals = [
            r"\[INTERNAL_ONLY\].*?\[/INTERNAL_ONLY\]",
            r"SECRET:\s*\S+",
        ]
        config = DataFilterConfig(custom_removal_patterns=custom_removals)

        assert len(config.custom_removal_patterns) == 2

    def test_blocked_patterns(self):
        """Blocked patterns can be configured."""
        blocked = ["known_attack_1", "known_attack_2"]
        config = DetectorConfig(blocked_patterns=blocked)

        assert len(config.blocked_patterns) == 2
        assert "known_attack_1" in config.blocked_patterns


class TestAllowlistBlocklist:
    """Tests for allowlist and blocklist configuration."""

    def test_allowed_users(self):
        """Allowed users can be configured."""
        config = TrustedFilterConfig(
            allowed_users=["admin", "security-bot", "trusted-contributor"]
        )

        assert "admin" in config.allowed_users
        assert "security-bot" in config.allowed_users
        assert len(config.allowed_users) == 3

    def test_blocked_users(self):
        """Blocked users can be configured."""
        config = TrustedFilterConfig(
            blocked_users=["known-attacker", "spam-bot"]
        )

        assert "known-attacker" in config.blocked_users
        assert len(config.blocked_users) == 2

    def test_allowed_domains(self):
        """Allowed domains can be configured."""
        config = TrustedFilterConfig(
            allowed_domains=["example.com", "trusted-org.net"]
        )

        assert "example.com" in config.allowed_domains
        assert len(config.allowed_domains) == 2

    def test_blocked_domains(self):
        """Blocked domains can be configured."""
        config = TrustedFilterConfig(
            blocked_domains=["evil.com", "phishing-site.net"]
        )

        assert "evil.com" in config.blocked_domains
        assert len(config.blocked_domains) == 2

    def test_user_in_both_allowed_and_blocked(self):
        """User can appear in both lists (blocklist takes precedence)."""
        config = TrustedFilterConfig(
            allowed_users=["user1", "user2"],
            blocked_users=["user2"],  # user2 in both
        )

        assert "user2" in config.allowed_users
        assert "user2" in config.blocked_users


class TestPerformanceSettings:
    """Tests for performance-related configuration."""

    def test_caching_enabled_by_default(self):
        """Caching should be enabled by default."""
        config = Config.default()
        assert config.enable_caching is True

    def test_caching_can_be_disabled(self):
        """Caching can be disabled."""
        config = Config(enable_caching=False)
        assert config.enable_caching is False

    def test_cache_ttl_configurable(self):
        """Cache TTL is configurable."""
        config = Config(cache_ttl_seconds=7200)
        assert config.cache_ttl_seconds == 7200

    def test_max_concurrent_requests_configurable(self):
        """Max concurrent requests is configurable."""
        config = Config(max_concurrent_requests=50)
        assert config.max_concurrent_requests == 50

    def test_request_timeout_configurable(self):
        """Request timeout is configurable."""
        config = Config(request_timeout_seconds=60.0)
        assert config.request_timeout_seconds == 60.0


class TestRiskThresholds:
    """Tests for risk threshold configuration."""

    def test_block_threshold_default(self):
        """Block threshold should default to HIGH."""
        config = Config.default()
        assert config.block_threshold == RiskLevel.HIGH

    def test_warn_threshold_default(self):
        """Warn threshold should default to MEDIUM."""
        config = Config.default()
        assert config.warn_threshold == RiskLevel.MEDIUM

    def test_custom_block_threshold(self):
        """Block threshold can be customized."""
        config = Config(block_threshold=RiskLevel.MEDIUM)
        assert config.block_threshold == RiskLevel.MEDIUM

    def test_custom_warn_threshold(self):
        """Warn threshold can be customized."""
        config = Config(warn_threshold=RiskLevel.LOW)
        assert config.warn_threshold == RiskLevel.LOW

    def test_strict_has_lower_block_threshold(self):
        """Strict config should have lower block threshold."""
        strict = Config.strict()
        default = Config.default()

        assert strict.block_threshold <= default.block_threshold

    def test_permissive_has_higher_block_threshold(self):
        """Permissive config should have higher block threshold."""
        permissive = Config.permissive()
        default = Config.default()

        assert permissive.block_threshold >= default.block_threshold


class TestMLModelConfig:
    """Tests for ML model configuration."""

    def test_ml_model_defaults(self):
        """ML model should have correct defaults."""
        config = DetectorConfig()

        assert config.use_ml_model is True
        assert config.ml_model_name == "microsoft/deberta-v3-base"
        assert config.ml_batch_size == 8
        assert config.ml_max_length == 512

    def test_ml_model_can_be_disabled(self):
        """ML model can be disabled."""
        config = DetectorConfig(use_ml_model=False)
        assert config.use_ml_model is False

    def test_custom_ml_model_name(self):
        """Custom ML model name can be set."""
        config = DetectorConfig(ml_model_name="custom/model-name")
        assert config.ml_model_name == "custom/model-name"

    def test_ml_batch_size_configurable(self):
        """ML batch size is configurable."""
        config = DetectorConfig(ml_batch_size=16)
        assert config.ml_batch_size == 16

    def test_ml_max_length_configurable(self):
        """ML max length is configurable."""
        config = DetectorConfig(ml_max_length=1024)
        assert config.ml_max_length == 1024


class TestContentFilteringFlags:
    """Tests for content filtering flags."""

    def test_all_content_types_filtered_by_default(self):
        """All content types should be filtered by default."""
        config = TrustedFilterConfig()

        assert config.filter_issue_content is True
        assert config.filter_comments is True
        assert config.filter_file_content is True
        assert config.filter_wiki_pages is True

    def test_selectively_disable_filtering(self):
        """Content filtering can be selectively disabled."""
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


class TestSanitizationModes:
    """Tests for sanitization mode configuration."""

    def test_sanitization_modes(self):
        """Different sanitization modes should be supported."""
        modes = ["remove", "mask", "escape", "tag"]

        for mode in modes:
            config = DataFilterConfig(mode=mode)
            assert config.mode == mode

    def test_aggressiveness_levels(self):
        """Different aggressiveness levels should be supported."""
        levels = ["minimal", "balanced", "aggressive"]

        for level in levels:
            config = DataFilterConfig(aggressiveness=level)
            assert config.aggressiveness == level

    def test_code_preservation_flags(self):
        """Code preservation flags should work."""
        config = DataFilterConfig(
            preserve_code_context=True,
            preserve_documentation=True,
        )

        assert config.preserve_code_context is True
        assert config.preserve_documentation is True


class TestFenceConfiguration:
    """Tests for prompt fencing configuration."""

    def test_fence_formats(self):
        """Different fence formats should be supported."""
        formats = ["xml", "markdown", "json", "delimiter"]

        for fmt in formats:
            config = PromptFenceConfig(fence_format=fmt)
            assert config.fence_format == fmt

    def test_custom_fence_delimiters(self):
        """Custom fence delimiters can be set."""
        config = PromptFenceConfig(
            trusted_prefix="[START_TRUSTED]",
            trusted_suffix="[END_TRUSTED]",
            untrusted_prefix="[START_UNTRUSTED]",
            untrusted_suffix="[END_UNTRUSTED]",
        )

        assert config.trusted_prefix == "[START_TRUSTED]"
        assert config.trusted_suffix == "[END_TRUSTED]"

    def test_signature_algorithm_configurable(self):
        """Signature algorithm is configurable."""
        config = PromptFenceConfig(signature_algorithm="sha256")
        assert config.signature_algorithm == "sha256"

    def test_metadata_flags(self):
        """Metadata inclusion flags should work."""
        config = PromptFenceConfig(
            include_metadata=True,
            include_trust_level=True,
            include_source_type=True,
        )

        assert config.include_metadata is True
        assert config.include_trust_level is True
        assert config.include_source_type is True
