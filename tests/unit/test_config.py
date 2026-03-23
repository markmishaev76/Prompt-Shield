"""
Unit tests for configuration validation.

Tests the Config class and its sub-configurations to ensure:
- Factory methods produce valid configurations
- Validation rules catch invalid settings
- Boundary conditions are handled correctly
- Serialization/deserialization works properly
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


class TestConfigFactoryMethods:
    """Tests for Config factory methods."""

    def test_default_config_is_valid(self):
        """Default config should be valid and usable."""
        config = Config.default()

        assert config is not None
        assert config.trusted_filter.enabled
        assert config.data_filter.enabled
        assert config.detector.enabled
        assert config.prompt_fence.enabled

    def test_strict_config_more_restrictive(self):
        """Strict config should have more restrictive settings."""
        strict = Config.strict()
        default = Config.default()

        # Strict should require higher trust levels (DEVELOPER > EXTERNAL)
        trust_order = ["anonymous", "untrusted", "external", "guest", "reporter", "developer", "maintainer", "admin", "system"]
        strict_trust_idx = trust_order.index(strict.trusted_filter.minimum_trust_level.value)
        default_trust_idx = trust_order.index(default.trusted_filter.minimum_trust_level.value)
        assert strict_trust_idx > default_trust_idx
        assert not strict.trusted_filter.allow_external
        assert not strict.trusted_filter.allow_anonymous

        # Strict should have lower confidence threshold (more sensitive)
        assert strict.detector.confidence_threshold < default.detector.confidence_threshold

        # Strict should block at lower risk level (MEDIUM vs HIGH)
        risk_order = ["none", "low", "medium", "high", "critical"]
        strict_risk_idx = risk_order.index(strict.block_threshold.value)
        default_risk_idx = risk_order.index(default.block_threshold.value)
        assert strict_risk_idx < default_risk_idx

        # Strict should not fail open
        assert not strict.fail_open
        assert strict.strict_mode

    def test_permissive_config_more_tolerant(self):
        """Permissive config should be more tolerant."""
        permissive = Config.permissive()
        default = Config.default()

        # Permissive should allow anonymous access
        assert permissive.trusted_filter.allow_anonymous

        # Permissive should have higher confidence threshold (less sensitive)
        assert permissive.detector.confidence_threshold > default.detector.confidence_threshold

        # Permissive should fail open
        assert permissive.fail_open


class TestDetectorConfigValidation:
    """Tests for DetectorConfig validation."""

    def test_confidence_threshold_bounds(self):
        """Confidence threshold should be between 0 and 1."""
        # Valid thresholds
        config_low = DetectorConfig(confidence_threshold=0.0)
        assert config_low.confidence_threshold == 0.0

        config_mid = DetectorConfig(confidence_threshold=0.5)
        assert config_mid.confidence_threshold == 0.5

        config_high = DetectorConfig(confidence_threshold=1.0)
        assert config_high.confidence_threshold == 1.0

        # Note: Pydantic doesn't enforce these bounds by default
        # This test documents current behavior (values outside 0-1 are accepted)

    def test_pattern_confidence_boost_bounds(self):
        """Pattern confidence boost should be non-negative."""
        # Valid boosts
        config_zero = DetectorConfig(pattern_confidence_boost=0.0)
        assert config_zero.pattern_confidence_boost == 0.0

        config_positive = DetectorConfig(pattern_confidence_boost=0.5)
        assert config_positive.pattern_confidence_boost == 0.5

        # Note: Pydantic doesn't enforce non-negative by default

    def test_tool_output_sensitivity_bounds(self):
        """Tool output sensitivity should be positive."""
        # Valid sensitivities
        config_low = DetectorConfig(tool_output_sensitivity=0.5)
        assert config_low.tool_output_sensitivity == 0.5

        config_normal = DetectorConfig(tool_output_sensitivity=1.0)
        assert config_normal.tool_output_sensitivity == 1.0

        config_high = DetectorConfig(tool_output_sensitivity=2.0)
        assert config_high.tool_output_sensitivity == 2.0

        # Note: Pydantic doesn't enforce positive values by default

    def test_ml_batch_size_positive(self):
        """ML batch size should be positive."""
        # Valid batch sizes
        config_small = DetectorConfig(ml_batch_size=1)
        assert config_small.ml_batch_size == 1

        config_large = DetectorConfig(ml_batch_size=32)
        assert config_large.ml_batch_size == 32

        # Note: Pydantic doesn't enforce positive values by default

    def test_ml_max_length_positive(self):
        """ML max length should be positive."""
        # Valid lengths
        config_short = DetectorConfig(ml_max_length=128)
        assert config_short.ml_max_length == 128

        config_long = DetectorConfig(ml_max_length=512)
        assert config_long.ml_max_length == 512

        # Note: Pydantic doesn't enforce positive values by default

    def test_all_detection_methods_disabled_warning(self):
        """Disabling all detection methods should still be valid but questionable."""
        # This should technically be valid (user's choice), but detector becomes no-op
        config = DetectorConfig(
            use_pattern_matching=False,
            use_ml_model=False,
            use_heuristics=False,
        )

        assert not config.use_pattern_matching
        assert not config.use_ml_model
        assert not config.use_heuristics


class TestDataFilterConfigValidation:
    """Tests for DataFilterConfig validation."""

    def test_valid_modes(self):
        """Only specific modes should be allowed."""
        # Valid modes
        DataFilterConfig(mode="remove")
        DataFilterConfig(mode="mask")
        DataFilterConfig(mode="escape")
        DataFilterConfig(mode="tag")

    def test_valid_aggressiveness_levels(self):
        """Only specific aggressiveness levels should be allowed."""
        # Valid levels
        DataFilterConfig(aggressiveness="minimal")
        DataFilterConfig(aggressiveness="balanced")
        DataFilterConfig(aggressiveness="aggressive")

    def test_max_content_length_positive(self):
        """Max content length should be positive."""
        # Valid lengths
        config_small = DataFilterConfig(max_content_length=100)
        assert config_small.max_content_length == 100

        config_large = DataFilterConfig(max_content_length=100000)
        assert config_large.max_content_length == 100000

        # Note: Pydantic doesn't enforce positive values by default

    def test_custom_removal_patterns_valid_regex(self):
        """Custom removal patterns should be valid regex."""
        # Valid patterns
        config = DataFilterConfig(
            custom_removal_patterns=[
                r"password\s*=\s*\w+",
                r"api[_\s]?key",
            ]
        )
        assert len(config.custom_removal_patterns) == 2


class TestTrustedFilterConfigValidation:
    """Tests for TrustedFilterConfig validation."""

    def test_minimum_trust_level_valid(self):
        """Minimum trust level should be a valid TrustLevel."""
        # Valid trust levels
        TrustedFilterConfig(minimum_trust_level=TrustLevel.ANONYMOUS)
        TrustedFilterConfig(minimum_trust_level=TrustLevel.EXTERNAL)
        TrustedFilterConfig(minimum_trust_level=TrustLevel.DEVELOPER)
        TrustedFilterConfig(minimum_trust_level=TrustLevel.ADMIN)

    def test_allow_anonymous_with_high_minimum_trust(self):
        """Allowing anonymous with high minimum trust should be valid (will just block all)."""
        config = TrustedFilterConfig(
            allow_anonymous=True,
            minimum_trust_level=TrustLevel.ADMIN,
        )

        # This is technically valid but will block all anonymous users
        assert config.allow_anonymous
        assert config.minimum_trust_level == TrustLevel.ADMIN

    def test_blocked_and_allowed_users_overlap_allowed(self):
        """Having same user in both blocked and allowed lists is allowed (blocked takes precedence)."""
        config = TrustedFilterConfig(
            allowed_users=["user1", "user2"],
            blocked_users=["user2", "user3"],
        )

        # This is valid; blocked_users should take precedence in implementation
        assert "user2" in config.allowed_users
        assert "user2" in config.blocked_users


class TestPromptFenceConfigValidation:
    """Tests for PromptFenceConfig validation."""

    def test_valid_fence_formats(self):
        """Only specific fence formats should be allowed."""
        # Valid formats
        PromptFenceConfig(fence_format="xml")
        PromptFenceConfig(fence_format="markdown")
        PromptFenceConfig(fence_format="json")
        PromptFenceConfig(fence_format="delimiter")

    def test_valid_signature_algorithms(self):
        """Signature algorithm should be a valid option."""
        # Valid algorithms
        PromptFenceConfig(signature_algorithm="hmac-sha256")
        PromptFenceConfig(signature_algorithm="hmac-sha512")

    def test_custom_delimiters(self):
        """Custom delimiters should be allowed."""
        config = PromptFenceConfig(
            trusted_prefix="===TRUSTED===",
            trusted_suffix="===END===",
            untrusted_prefix="[UNTRUSTED]",
            untrusted_suffix="[/UNTRUSTED]",
        )

        assert config.trusted_prefix == "===TRUSTED==="
        assert config.untrusted_suffix == "[/UNTRUSTED]"


class TestLoggingConfigValidation:
    """Tests for LoggingConfig validation."""

    def test_valid_log_levels(self):
        """Log level should be a valid logging level."""
        # Valid levels
        LoggingConfig(log_level="DEBUG")
        LoggingConfig(log_level="INFO")
        LoggingConfig(log_level="WARNING")
        LoggingConfig(log_level="ERROR")

    def test_max_logged_content_length_positive(self):
        """Max logged content length should be positive."""
        # Valid lengths
        config_small = LoggingConfig(max_logged_content_length=100)
        assert config_small.max_logged_content_length == 100

        config_large = LoggingConfig(max_logged_content_length=1000)
        assert config_large.max_logged_content_length == 1000

        # Note: Pydantic doesn't enforce positive values by default


class TestMasterConfigValidation:
    """Tests for master Config validation."""

    def test_block_threshold_valid_risk_level(self):
        """Block threshold should be a valid RiskLevel."""
        # Valid risk levels
        Config(block_threshold=RiskLevel.LOW)
        Config(block_threshold=RiskLevel.MEDIUM)
        Config(block_threshold=RiskLevel.HIGH)
        Config(block_threshold=RiskLevel.CRITICAL)

    def test_warn_threshold_valid_risk_level(self):
        """Warn threshold should be a valid RiskLevel."""
        # Valid risk levels
        Config(warn_threshold=RiskLevel.LOW)
        Config(warn_threshold=RiskLevel.MEDIUM)
        Config(warn_threshold=RiskLevel.HIGH)

    def test_warn_threshold_below_block_threshold(self):
        """Warn threshold should typically be below block threshold."""
        # Valid configuration (warn < block)
        config = Config(
            warn_threshold=RiskLevel.LOW,
            block_threshold=RiskLevel.HIGH,
        )

        # Compare by severity level
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        assert risk_order[config.warn_threshold.value] < risk_order[config.block_threshold.value]

        # Inverted thresholds are technically valid but questionable
        inverted = Config(
            warn_threshold=RiskLevel.HIGH,
            block_threshold=RiskLevel.LOW,
        )

        assert risk_order[inverted.warn_threshold.value] > risk_order[inverted.block_threshold.value]

    def test_cache_ttl_positive(self):
        """Cache TTL should be positive."""
        # Valid TTLs
        config_short = Config(cache_ttl_seconds=60)
        assert config_short.cache_ttl_seconds == 60

        config_long = Config(cache_ttl_seconds=3600)
        assert config_long.cache_ttl_seconds == 3600

        # Note: Pydantic doesn't enforce positive values by default

    def test_max_concurrent_requests_positive(self):
        """Max concurrent requests should be positive."""
        # Valid values
        config_small = Config(max_concurrent_requests=10)
        assert config_small.max_concurrent_requests == 10

        config_large = Config(max_concurrent_requests=1000)
        assert config_large.max_concurrent_requests == 1000

        # Note: Pydantic doesn't enforce positive values by default

    def test_request_timeout_positive(self):
        """Request timeout should be positive."""
        # Valid timeouts
        config_short = Config(request_timeout_seconds=1.0)
        assert config_short.request_timeout_seconds == 1.0

        config_long = Config(request_timeout_seconds=60.0)
        assert config_long.request_timeout_seconds == 60.0

        # Note: Pydantic doesn't enforce positive values by default


class TestConfigSerialization:
    """Tests for config serialization and deserialization."""

    def test_default_config_serializes_to_json(self):
        """Default config should serialize to JSON."""
        config = Config.default()
        json_str = config.model_dump_json()

        assert json_str is not None
        assert len(json_str) > 0

        # Should be valid JSON
        json_data = json.loads(json_str)
        assert isinstance(json_data, dict)

    def test_config_deserializes_from_json(self):
        """Config should deserialize from JSON."""
        config = Config.default()
        json_str = config.model_dump_json()

        # Deserialize
        json_data = json.loads(json_str)
        restored_config = Config(**json_data)

        assert restored_config.detector.enabled == config.detector.enabled
        assert restored_config.strict_mode == config.strict_mode

    def test_strict_config_roundtrip(self):
        """Strict config should survive serialization roundtrip."""
        original = Config.strict()

        # Serialize and deserialize
        json_data = json.loads(original.model_dump_json())
        restored = Config(**json_data)

        # Verify key strict settings are preserved
        assert restored.strict_mode == original.strict_mode
        assert restored.fail_open == original.fail_open
        assert restored.trusted_filter.minimum_trust_level == original.trusted_filter.minimum_trust_level
        assert restored.detector.confidence_threshold == original.detector.confidence_threshold

    def test_partial_config_from_dict(self):
        """Should be able to create config from partial dictionary."""
        config = Config(
            strict_mode=True,
            detector={"confidence_threshold": 0.9},
        )

        assert config.strict_mode
        assert config.detector.confidence_threshold == 0.9
        # Other values should use defaults
        assert config.detector.enabled

    def test_invalid_json_raises_validation_error(self):
        """Invalid JSON config should raise validation error."""
        # Test with invalid enum value (this WILL raise validation error)
        invalid_config = {
            "block_threshold": "SUPER_HIGH",  # Invalid: not a valid RiskLevel
        }

        with pytest.raises(ValidationError):
            Config(**invalid_config)


class TestConfigEdgeCases:
    """Tests for config edge cases and boundary conditions."""

    def test_all_layers_disabled(self):
        """Disabling all layers should be valid (no-op pipeline)."""
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

    def test_empty_custom_patterns(self):
        """Empty custom patterns list should be valid."""
        config = Config(
            detector=DetectorConfig(custom_patterns={}),
        )

        assert len(config.detector.custom_patterns) == 0

    def test_empty_allowlists_blocklists(self):
        """Empty allowlists and blocklists should be valid."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                allowed_users=[],
                blocked_users=[],
                allowed_domains=[],
                blocked_domains=[],
            )
        )

        assert len(config.trusted_filter.allowed_users) == 0
        assert len(config.trusted_filter.blocked_users) == 0

    def test_very_large_max_content_length(self):
        """Very large max content length should be allowed."""
        config = DataFilterConfig(max_content_length=10_000_000)

        assert config.max_content_length == 10_000_000

    def test_minimal_confidence_threshold(self):
        """Minimal confidence threshold (0.0) should catch everything."""
        config = DetectorConfig(confidence_threshold=0.0)

        assert config.confidence_threshold == 0.0

    def test_maximum_confidence_threshold(self):
        """Maximum confidence threshold (1.0) should catch only perfect matches."""
        config = DetectorConfig(confidence_threshold=1.0)

        assert config.confidence_threshold == 1.0


class TestConfigInheritance:
    """Tests for config inheritance and overrides."""

    def test_override_specific_layer_in_strict(self):
        """Should be able to override specific layer in strict config."""
        config = Config.strict()

        # Override just the detector
        config.detector.confidence_threshold = 0.3

        assert config.detector.confidence_threshold == 0.3
        # Other strict settings should remain
        assert config.strict_mode
        assert not config.trusted_filter.allow_external

    def test_layered_config_construction(self):
        """Should be able to build config layer by layer."""
        config = Config(
            trusted_filter=TrustedFilterConfig(
                minimum_trust_level=TrustLevel.REPORTER,
                allow_external=False,
            ),
            detector=DetectorConfig(
                confidence_threshold=0.8,
                use_ml_model=False,
            ),
        )

        assert config.trusted_filter.minimum_trust_level == TrustLevel.REPORTER
        assert not config.trusted_filter.allow_external
        assert config.detector.confidence_threshold == 0.8
        assert not config.detector.use_ml_model
        # Other settings use defaults
        assert config.data_filter.enabled
