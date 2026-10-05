"""
Unit tests for Enterprise Feature Flags.

Tests the hierarchical configuration system for controlling
scanning behavior at global, organization, and project levels.
"""

import json
import tempfile
from pathlib import Path

import pytest

from prompt_shield.enterprise.feature_flags import (
    ActionOnDetection,
    FeatureFlagConfig,
    FeatureFlags,
    ScanningLevel,
    create_default_flags,
)


class TestScanningLevelEnum:
    """Tests for ScanningLevel enum."""

    def test_all_scanning_levels_defined(self):
        """All scanning levels should be defined."""
        assert ScanningLevel.OFF == "off"
        assert ScanningLevel.QUICK == "quick"
        assert ScanningLevel.STANDARD == "standard"
        assert ScanningLevel.DEEP == "deep"

    def test_scanning_level_from_string(self):
        """Should create ScanningLevel from string."""
        assert ScanningLevel("off") == ScanningLevel.OFF
        assert ScanningLevel("quick") == ScanningLevel.QUICK
        assert ScanningLevel("standard") == ScanningLevel.STANDARD
        assert ScanningLevel("deep") == ScanningLevel.DEEP


class TestActionOnDetectionEnum:
    """Tests for ActionOnDetection enum."""

    def test_all_actions_defined(self):
        """All actions should be defined."""
        assert ActionOnDetection.LOG_ONLY == "log_only"
        assert ActionOnDetection.WARN == "warn"
        assert ActionOnDetection.SANITIZE == "sanitize"
        assert ActionOnDetection.BLOCK == "block"

    def test_action_from_string(self):
        """Should create ActionOnDetection from string."""
        assert ActionOnDetection("log_only") == ActionOnDetection.LOG_ONLY
        assert ActionOnDetection("warn") == ActionOnDetection.WARN
        assert ActionOnDetection("sanitize") == ActionOnDetection.SANITIZE
        assert ActionOnDetection("block") == ActionOnDetection.BLOCK


class TestFeatureFlagConfig:
    """Tests for FeatureFlagConfig dataclass."""

    def test_default_global_config(self):
        """Global config should have sensible defaults."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.scope_type == "global"
        assert config.scope_id is None
        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.STANDARD
        assert config.action_on_detection == ActionOnDetection.SANITIZE

    def test_org_config_with_id(self):
        """Organization config should store org ID."""
        config = FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-123",
        )

        assert config.scope_type == "organization"
        assert config.scope_id == "org-123"

    def test_project_config_with_id(self):
        """Project config should store project ID."""
        config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-456",
        )

        assert config.scope_type == "project"
        assert config.scope_id == "proj-456"

    def test_all_scan_types_enabled_by_default(self):
        """All content types should be scanned by default."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.scan_issues is True
        assert config.scan_pull_requests is True
        assert config.scan_comments is True
        assert config.scan_file_contents is True

    def test_commit_messages_not_scanned_by_default(self):
        """Commit messages should not be scanned by default (low risk)."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.scan_commit_messages is False

    def test_all_detection_types_enabled_by_default(self):
        """All attack detection types should be enabled by default."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.detect_credential_exfiltration is True
        assert config.detect_action_steering is True
        assert config.detect_system_prompt_extraction is True
        assert config.detect_privilege_escalation is True
        assert config.detect_data_exfiltration is True

    def test_all_layers_enabled_by_default(self):
        """All defense layers should be enabled by default."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.enable_trusted_filter is True
        assert config.enable_data_filter is True
        assert config.enable_detector is True
        assert config.enable_prompt_fence is True

    def test_performance_settings_have_defaults(self):
        """Performance settings should have reasonable defaults."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.max_payload_size == 100000
        assert config.timeout_ms == 5000

    def test_alerting_enabled_by_default(self):
        """Alerting should be enabled by default."""
        config = FeatureFlagConfig(scope_type="global")

        assert config.alert_on_detection is True
        assert config.alert_webhook_url is None


class TestFeatureFlagConfigSerialization:
    """Tests for serialization and deserialization."""

    def test_to_dict_contains_all_fields(self):
        """to_dict should serialize all configuration fields."""
        config = FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-789",
            scanning_enabled=False,
            scanning_level=ScanningLevel.QUICK,
        )

        data = config.to_dict()

        assert data["scope_type"] == "project"
        assert data["scope_id"] == "proj-789"
        assert data["scanning_enabled"] is False
        assert data["scanning_level"] == "quick"
        assert "action_on_detection" in data
        assert "scan_issues" in data
        assert "detect_credential_exfiltration" in data

    def test_from_dict_restores_config(self):
        """from_dict should restore configuration from dict."""
        data = {
            "scope_type": "organization",
            "scope_id": "org-456",
            "scanning_enabled": True,
            "scanning_level": "deep",
            "action_on_detection": "block",
            "scan_issues": False,
            "detect_credential_exfiltration": False,
        }

        config = FeatureFlagConfig.from_dict(data)

        assert config.scope_type == "organization"
        assert config.scope_id == "org-456"
        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.DEEP
        assert config.action_on_detection == ActionOnDetection.BLOCK
        assert config.scan_issues is False
        assert config.detect_credential_exfiltration is False

    def test_from_dict_uses_defaults_for_missing_fields(self):
        """from_dict should use defaults when fields are missing."""
        data = {
            "scope_type": "global",
        }

        config = FeatureFlagConfig.from_dict(data)

        assert config.scanning_enabled is True
        assert config.scanning_level == ScanningLevel.STANDARD
        assert config.scan_issues is True

    def test_roundtrip_serialization(self):
        """Configuration should survive to_dict -> from_dict roundtrip."""
        original = FeatureFlagConfig(
            scope_type="project",
            scope_id="test-123",
            scanning_level=ScanningLevel.DEEP,
            action_on_detection=ActionOnDetection.BLOCK,
            scan_issues=False,
            scan_comments=True,
            detect_credential_exfiltration=False,
            max_payload_size=50000,
        )

        data = original.to_dict()
        restored = FeatureFlagConfig.from_dict(data)

        assert restored.scope_type == original.scope_type
        assert restored.scope_id == original.scope_id
        assert restored.scanning_level == original.scanning_level
        assert restored.action_on_detection == original.action_on_detection
        assert restored.scan_issues == original.scan_issues
        assert restored.detect_credential_exfiltration == original.detect_credential_exfiltration
        assert restored.max_payload_size == original.max_payload_size


class TestFeatureFlagsHierarchy:
    """Tests for hierarchical configuration (global > org > project)."""

    def test_global_config_set_and_retrieved(self):
        """Should set and retrieve global configuration."""
        flags = FeatureFlags()
        config = FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.QUICK,
        )

        flags.set_global_config(config)
        retrieved = flags.get_config()

        assert retrieved.scanning_level == ScanningLevel.QUICK

    def test_org_config_overrides_global(self):
        """Organization config should override global config."""
        flags = FeatureFlags()

        # Set global
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.STANDARD,
        ))

        # Set org override
        flags.set_org_config("org-1", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-1",
            scanning_level=ScanningLevel.DEEP,
        ))

        # Retrieve with org context
        config = flags.get_config(org_id="org-1")
        assert config.scanning_level == ScanningLevel.DEEP

    def test_project_config_overrides_org(self):
        """Project config should override organization config."""
        flags = FeatureFlags()

        # Set global
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.STANDARD,
        ))

        # Set org
        flags.set_org_config("org-1", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-1",
            scanning_level=ScanningLevel.DEEP,
        ))

        # Set project override
        flags.set_project_config("proj-1", FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-1",
            scanning_level=ScanningLevel.QUICK,
        ))

        # Retrieve with project context
        config = flags.get_config(project_id="proj-1", org_id="org-1")
        assert config.scanning_level == ScanningLevel.QUICK

    def test_project_without_org_uses_global(self):
        """Project lookup without org should fall back to global."""
        flags = FeatureFlags()

        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.STANDARD,
        ))

        config = flags.get_config(project_id="unknown-project")
        assert config.scanning_level == ScanningLevel.STANDARD

    def test_org_without_config_uses_global(self):
        """Organization without config should use global defaults."""
        flags = FeatureFlags()

        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            action_on_detection=ActionOnDetection.BLOCK,
        ))

        config = flags.get_config(org_id="unknown-org")
        assert config.action_on_detection == ActionOnDetection.BLOCK


class TestFeatureFlagsConvenienceMethods:
    """Tests for convenience query methods."""

    def test_is_scanning_enabled_global(self):
        """Should check if scanning is enabled globally."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=False,
        ))

        assert flags.is_scanning_enabled() is False

    def test_is_scanning_enabled_project_override(self):
        """Should respect project-level scanning toggle."""
        flags = FeatureFlags()

        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=True,
        ))

        flags.set_project_config("proj-1", FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-1",
            scanning_enabled=False,
        ))

        assert flags.is_scanning_enabled(project_id="proj-1") is False

    def test_should_scan_content_type_issue(self):
        """Should check if issues should be scanned."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scan_issues=True,
        ))

        assert flags.should_scan_content_type("issue") is True

    def test_should_scan_content_type_disabled(self):
        """Should not scan when content type is disabled."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scan_pull_requests=False,
        ))

        assert flags.should_scan_content_type("pull_request") is False

    def test_should_scan_respects_global_scanning_disabled(self):
        """Should not scan any content when scanning is globally disabled."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=False,
            scan_issues=True,  # Even though enabled
        ))

        assert flags.should_scan_content_type("issue") is False

    def test_should_scan_content_type_unknown_defaults_true(self):
        """Unknown content types should default to scanning enabled."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=True,
        ))

        assert flags.should_scan_content_type("unknown_type") is True


class TestFeatureFlagsPersistence:
    """Tests for saving and loading configuration."""

    def test_export_config_includes_all_scopes(self):
        """Export should include global, org, and project configs."""
        flags = FeatureFlags()

        flags.set_global_config(FeatureFlagConfig(scope_type="global"))
        flags.set_org_config("org-1", FeatureFlagConfig(scope_type="organization", scope_id="org-1"))
        flags.set_project_config("proj-1", FeatureFlagConfig(scope_type="project", scope_id="proj-1"))

        exported = flags.export_config()

        assert "global" in exported
        assert "organizations" in exported
        assert "projects" in exported
        assert "org-1" in exported["organizations"]
        assert "proj-1" in exported["projects"]

    def test_import_config_restores_all_scopes(self):
        """Import should restore all configurations."""
        data = {
            "global": {
                "scope_type": "global",
                "scanning_level": "deep",
            },
            "organizations": {
                "org-1": {
                    "scope_type": "organization",
                    "scope_id": "org-1",
                    "scanning_level": "quick",
                }
            },
            "projects": {
                "proj-1": {
                    "scope_type": "project",
                    "scope_id": "proj-1",
                    "scanning_level": "standard",
                }
            }
        }

        flags = FeatureFlags()
        flags.import_config(data)

        global_config = flags.get_config()
        assert global_config.scanning_level == ScanningLevel.DEEP

        org_config = flags.get_config(org_id="org-1")
        assert org_config.scanning_level == ScanningLevel.QUICK

        proj_config = flags.get_config(project_id="proj-1")
        assert proj_config.scanning_level == ScanningLevel.STANDARD

    def test_save_and_load_from_file(self):
        """Should save to and load from JSON file."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_level=ScanningLevel.DEEP,
            action_on_detection=ActionOnDetection.BLOCK,
        ))
        flags.set_org_config("org-test", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-test",
            scan_issues=False,
        ))

        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            flags.save_to_file(temp_path)

            # Load into new instance
            new_flags = FeatureFlags()
            new_flags.load_from_file(temp_path)

            # Verify restoration
            config = new_flags.get_config()
            assert config.scanning_level == ScanningLevel.DEEP
            assert config.action_on_detection == ActionOnDetection.BLOCK

            org_config = new_flags.get_config(org_id="org-test")
            assert org_config.scan_issues is False
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_exported_json_is_valid(self):
        """Exported configuration should be valid JSON."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(scope_type="global"))

        exported = flags.export_config()

        # Should be JSON serializable
        json_str = json.dumps(exported)
        assert json_str is not None

        # Should be deserializable
        parsed = json.loads(json_str)
        assert parsed == exported


class TestCreateDefaultFlags:
    """Tests for the convenience factory function."""

    def test_creates_feature_flags_instance(self):
        """Should create a FeatureFlags instance."""
        flags = create_default_flags()

        assert isinstance(flags, FeatureFlags)

    def test_default_flags_scanning_enabled(self):
        """Default flags should have scanning enabled."""
        flags = create_default_flags()

        assert flags.is_scanning_enabled() is True

    def test_default_flags_standard_level(self):
        """Default flags should use standard scanning level."""
        flags = create_default_flags()
        config = flags.get_config()

        assert config.scanning_level == ScanningLevel.STANDARD

    def test_default_flags_sanitize_action(self):
        """Default flags should sanitize on detection."""
        flags = create_default_flags()
        config = flags.get_config()

        assert config.action_on_detection == ActionOnDetection.SANITIZE


class TestFeatureFlagsEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_orgs_independent(self):
        """Multiple organizations should have independent configs."""
        flags = FeatureFlags()

        flags.set_org_config("org-1", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-1",
            scanning_level=ScanningLevel.QUICK,
        ))

        flags.set_org_config("org-2", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-2",
            scanning_level=ScanningLevel.DEEP,
        ))

        config1 = flags.get_config(org_id="org-1")
        config2 = flags.get_config(org_id="org-2")

        assert config1.scanning_level == ScanningLevel.QUICK
        assert config2.scanning_level == ScanningLevel.DEEP

    def test_multiple_projects_independent(self):
        """Multiple projects should have independent configs."""
        flags = FeatureFlags()

        flags.set_project_config("proj-1", FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-1",
            scan_issues=True,
        ))

        flags.set_project_config("proj-2", FeatureFlagConfig(
            scope_type="project",
            scope_id="proj-2",
            scan_issues=False,
        ))

        config1 = flags.get_config(project_id="proj-1")
        config2 = flags.get_config(project_id="proj-2")

        assert config1.scan_issues is True
        assert config2.scan_issues is False

    def test_scanning_disabled_overrides_all_content_types(self):
        """When scanning is disabled, no content types should be scanned."""
        flags = FeatureFlags()
        flags.set_global_config(FeatureFlagConfig(
            scope_type="global",
            scanning_enabled=False,
            scan_issues=True,
            scan_pull_requests=True,
            scan_comments=True,
        ))

        assert flags.should_scan_content_type("issue") is False
        assert flags.should_scan_content_type("pull_request") is False
        assert flags.should_scan_content_type("comment") is False

    def test_config_update_replaces_previous(self):
        """Setting config for same scope should replace previous config."""
        flags = FeatureFlags()

        flags.set_org_config("org-1", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-1",
            scanning_level=ScanningLevel.QUICK,
        ))

        flags.set_org_config("org-1", FeatureFlagConfig(
            scope_type="organization",
            scope_id="org-1",
            scanning_level=ScanningLevel.DEEP,
        ))

        config = flags.get_config(org_id="org-1")
        assert config.scanning_level == ScanningLevel.DEEP

    def test_empty_import_does_not_crash(self):
        """Importing empty config should not crash."""
        flags = FeatureFlags()
        flags.import_config({})

        # Should still have default global config
        config = flags.get_config()
        assert config is not None
