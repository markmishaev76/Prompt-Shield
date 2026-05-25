"""
Unit tests for Enterprise Feature Flags module.

Tests hierarchical configuration, feature flag management,
and priority handling (project > organization > global).
"""

import pytest
import tempfile
import json
from pathlib import Path

from prompt_shield.enterprise.feature_flags import (
    FeatureFlags,
    FeatureFlagConfig,
    ScanningLevel,
    ActionOnDetection,
    create_default_flags,
)


class TestFeatureFlagConfig:
    """Test FeatureFlagConfig dataclass and serialization."""

    def test_default_config(self):
        """Test default feature flag configuration."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.STANDARD
        assert config.action_on_detection == ActionOnDetection.SANITIZE
        assert config.scan_issues is True
        assert config.scan_pull_requests is True
        assert config.detect_credential_exfiltration is True

    def test_config_to_dict(self):
        """Test configuration serialization to dict."""
        config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-123",
            scanning_level=ScanningLevel.DEEP,
            action_on_detection=ActionOnDetection.BLOCK,
        )

        data = config.to_dict()

        assert data["scope_type"] == "project"
        assert data["scope_id"] == "proj-123"
        assert data["scanning_level"] == "deep"
        assert data["action_on_detection"] == "block"
        assert data["scanning_enabled"] is True

    def test_config_from_dict(self):
        """Test configuration deserialization from dict."""
        data = {
            "scope_type": "organization",
            "scope_id": "org-456",
            "scanning_enabled": False,
            "scanning_level": "quick",
            "action_on_detection": "log_only",
            "scan_issues": False,
            "detect_privilege_escalation": False,
        }

        config = FeatureFlagConfig.from_dict(data)

        assert config.scope_type == "organization"
        assert config.scope_id == "org-456"
        assert config.scanning_enabled is False
        assert config.scanning_level == ScanningLevel.QUICK
        assert config.action_on_detection == ActionOnDetection.LOG_ONLY
        assert config.scan_issues is False
        assert config.detect_privilege_escalation is False
        # Defaults should still apply
        assert config.scan_pull_requests is True

    def test_config_roundtrip(self):
        """Test config serialization roundtrip (to_dict -> from_dict)."""
        original = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-789",
            scanning_level=ScanningLevel.OFF,
            max_payload_size=50000,
            timeout_ms=3000,
        )

        data = original.to_dict()
        restored = FeatureFlagConfig.from_dict(data)

        assert restored.scope_type == original.scope_type
        assert restored.scope_id == original.scope_id
        assert restored.scanning_level == original.scanning_level
        assert restored.max_payload_size == original.max_payload_size
        assert restored.timeout_ms == original.timeout_ms


class TestFeatureFlags:
    """Test FeatureFlags hierarchical configuration manager."""

    def test_default_global_config(self):
        """Test feature flags with default global configuration."""
        flags = FeatureFlags()

        config = flags.get_config()

        assert config.scope_type == "global"
        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.STANDARD

    def test_set_global_config(self):
        """Test setting global configuration."""
        flags = FeatureFlags()

        global_config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.DEEP,
            action_on_detection=ActionOnDetection.BLOCK,
        )
        flags.set_global_config(global_config)

        config = flags.get_config()
        assert config.scanning_level == ScanningLevel.DEEP
        assert config.action_on_detection == ActionOnDetection.BLOCK

    def test_org_config_overrides_global(self):
        """Test organization config overrides global config."""
        flags = FeatureFlags()

        # Set global config
        global_config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.STANDARD,
            scan_issues=True,
        )
        flags.set_global_config(global_config)

        # Set org config
        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
            scanning_level=ScanningLevel.QUICK,
            scan_issues=False,
        )
        flags.set_org_config("org-123", org_config)

        # Without org_id, should use global
        global_result = flags.get_config()
        assert global_result.scanning_level == ScanningLevel.STANDARD
        assert global_result.scan_issues is True

        # With org_id, should use org config
        org_result = flags.get_config(org_id="org-123")
        assert org_result.scanning_level == ScanningLevel.QUICK
        assert org_result.scan_issues is False

    def test_project_config_overrides_org_and_global(self):
        """Test project config has highest priority."""
        flags = FeatureFlags()

        # Set global config
        global_config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.STANDARD,
            action_on_detection=ActionOnDetection.SANITIZE,
        )
        flags.set_global_config(global_config)

        # Set org config
        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-456",
            scanning_level=ScanningLevel.DEEP,
        )
        flags.set_org_config("org-456", org_config)

        # Set project config
        project_config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-789",
            scanning_level=ScanningLevel.OFF,
            action_on_detection=ActionOnDetection.LOG_ONLY,
        )
        flags.set_project_config("proj-789", project_config)

        # Project config should override both
        result = flags.get_config(project_id="proj-789", org_id="org-456")
        assert result.scanning_level == ScanningLevel.OFF
        assert result.action_on_detection == ActionOnDetection.LOG_ONLY

    def test_is_scanning_enabled(self):
        """Test scanning enabled check respects hierarchy."""
        flags = FeatureFlags()

        # Global: enabled
        assert flags.is_scanning_enabled() is True

        # Org: disabled
        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-disabled",
            scanning_enabled=False,
        )
        flags.set_org_config("org-disabled", org_config)
        assert flags.is_scanning_enabled(org_id="org-disabled") is False

        # Project: enabled (overrides org)
        project_config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-enabled",
            scanning_enabled=True,
        )
        flags.set_project_config("proj-enabled", project_config)
        assert flags.is_scanning_enabled(
            project_id="proj-enabled",
            org_id="org-disabled"
        ) is True

    def test_should_scan_content_type(self):
        """Test content type scanning configuration."""
        flags = FeatureFlags()

        # Default: all content types enabled
        assert flags.should_scan_content_type("issue") is True
        assert flags.should_scan_content_type("pull_request") is True
        assert flags.should_scan_content_type("comment") is True
        assert flags.should_scan_content_type("file") is True
        assert flags.should_scan_content_type("commit") is False  # Default off

        # Org config: disable PR scanning
        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
            scan_pull_requests=False,
        )
        flags.set_org_config("org-123", org_config)

        assert flags.should_scan_content_type("issue", org_id="org-123") is True
        assert flags.should_scan_content_type("pull_request", org_id="org-123") is False

    def test_scanning_disabled_returns_false_for_all_content_types(self):
        """Test that when scanning is disabled, no content types are scanned."""
        flags = FeatureFlags()

        config = FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=False,
        )
        flags.set_global_config(config)

        assert flags.should_scan_content_type("issue") is False
        assert flags.should_scan_content_type("pull_request") is False
        assert flags.should_scan_content_type("comment") is False
        assert flags.should_scan_content_type("file") is False

    def test_export_import_config(self):
        """Test exporting and importing all configurations."""
        flags = FeatureFlags()

        # Set up multi-level config
        global_config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.DEEP,
        )
        flags.set_global_config(global_config)

        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
            scan_issues=False,
        )
        flags.set_org_config("org-123", org_config)

        project_config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-456",
            scanning_enabled=False,
        )
        flags.set_project_config("proj-456", project_config)

        # Export
        exported = flags.export_config()

        assert "global" in exported
        assert "organizations" in exported
        assert "projects" in exported
        assert exported["global"]["scanning_level"] == "deep"
        assert "org-123" in exported["organizations"]
        assert "proj-456" in exported["projects"]

        # Import into new instance
        new_flags = FeatureFlags()
        new_flags.import_config(exported)

        # Verify imported data
        assert new_flags.get_config().scanning_level == ScanningLevel.DEEP
        assert new_flags.get_config(org_id="org-123").scan_issues is False
        assert new_flags.get_config(project_id="proj-456").scanning_enabled is False

    def test_save_and_load_from_file(self):
        """Test saving and loading feature flags from JSON file."""
        flags = FeatureFlags()

        # Configure with some settings
        global_config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.QUICK,
            action_on_detection=ActionOnDetection.WARN,
        )
        flags.set_global_config(global_config)

        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-save-test",
            max_payload_size=200000,
        )
        flags.set_org_config("org-save-test", org_config)

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            flags.save_to_file(temp_path)

            # Load into new instance
            new_flags = FeatureFlags()
            new_flags.load_from_file(temp_path)

            # Verify loaded data
            loaded_global = new_flags.get_config()
            assert loaded_global.scanning_level == ScanningLevel.QUICK
            assert loaded_global.action_on_detection == ActionOnDetection.WARN

            loaded_org = new_flags.get_config(org_id="org-save-test")
            assert loaded_org.max_payload_size == 200000
        finally:
            Path(temp_path).unlink()


class TestScanningLevel:
    """Test ScanningLevel enum."""

    def test_scanning_level_values(self):
        """Test all scanning level enum values."""
        assert ScanningLevel.OFF.value == "off"
        assert ScanningLevel.QUICK.value == "quick"
        assert ScanningLevel.STANDARD.value == "standard"
        assert ScanningLevel.DEEP.value == "deep"


class TestActionOnDetection:
    """Test ActionOnDetection enum."""

    def test_action_on_detection_values(self):
        """Test all action on detection enum values."""
        assert ActionOnDetection.LOG_ONLY.value == "log_only"
        assert ActionOnDetection.WARN.value == "warn"
        assert ActionOnDetection.SANITIZE.value == "sanitize"
        assert ActionOnDetection.BLOCK.value == "block"


class TestCreateDefaultFlags:
    """Test create_default_flags convenience function."""

    def test_creates_flags_with_sensible_defaults(self):
        """Test that default flags are properly configured."""
        flags = create_default_flags()

        config = flags.get_config()

        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.STANDARD
        assert config.action_on_detection == ActionOnDetection.SANITIZE
        assert config.detect_credential_exfiltration is True
        assert config.detect_action_steering is True
        assert config.detect_system_prompt_extraction is True


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_scope_ids(self):
        """Test handling of None/empty scope IDs."""
        flags = FeatureFlags()

        # Should return global config
        config = flags.get_config(project_id=None, org_id=None)
        assert config.scope_type == "global"

    def test_nonexistent_org_id(self):
        """Test requesting config for non-configured org."""
        flags = FeatureFlags()

        # Should fall back to global config
        config = flags.get_config(org_id="nonexistent-org")
        assert config.scanning_enabled is True  # Global default

    def test_nonexistent_project_id(self):
        """Test requesting config for non-configured project."""
        flags = FeatureFlags()

        # Set org config
        org_config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-exists",
            scanning_level=ScanningLevel.QUICK,
        )
        flags.set_org_config("org-exists", org_config)

        # Request non-existent project in existing org
        config = flags.get_config(project_id="nonexistent-proj", org_id="org-exists")
        # Should use org config since project doesn't exist
        assert config.scanning_level == ScanningLevel.QUICK

    def test_unknown_content_type(self):
        """Test scanning unknown content type."""
        flags = FeatureFlags()

        # Unknown content type should default to True (scan by default)
        assert flags.should_scan_content_type("unknown_type") is True

    def test_multiple_org_configs(self):
        """Test multiple organization configurations."""
        flags = FeatureFlags()

        # Configure multiple orgs
        for i in range(5):
            org_id = f"org-{i}"
            config = FeatureFlagConfig(
                scope_type="organization",
                scope_id=org_id,
                max_payload_size=10000 * (i + 1),
            )
            flags.set_org_config(org_id, config)

        # Verify each org has its own config
        for i in range(5):
            org_id = f"org-{i}"
            config = flags.get_config(org_id=org_id)
            assert config.max_payload_size == 10000 * (i + 1)

    def test_overwrite_existing_config(self):
        """Test overwriting an existing configuration."""
        flags = FeatureFlags()

        # Set initial org config
        org_config1 = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
            scanning_level=ScanningLevel.QUICK,
        )
        flags.set_org_config("org-123", org_config1)

        # Overwrite with new config
        org_config2 = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
            scanning_level=ScanningLevel.DEEP,
            scan_issues=False,
        )
        flags.set_org_config("org-123", org_config2)

        # Should have new config
        config = flags.get_config(org_id="org-123")
        assert config.scanning_level == ScanningLevel.DEEP
        assert config.scan_issues is False
