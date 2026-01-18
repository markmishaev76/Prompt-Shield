"""
Feature Flags for Prompt Shield Enterprise

Provides fine-grained control over scanning features at:
- Global level (instance-wide)
- Organization/Namespace level  
- Project/Repository level

Based on GitLab's requirements for enterprise deployments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import json


class ScanningLevel(str, Enum):
    """Scanning intensity levels."""
    OFF = "off"           # No scanning
    QUICK = "quick"       # Fast pattern matching only
    STANDARD = "standard" # Pattern + basic heuristics
    DEEP = "deep"         # Full analysis including ML (if available)


class ActionOnDetection(str, Enum):
    """What to do when injection is detected."""
    LOG_ONLY = "log_only"       # Just log, don't block
    WARN = "warn"               # Warn but allow
    SANITIZE = "sanitize"       # Remove malicious content
    BLOCK = "block"             # Block the request entirely


@dataclass
class FeatureFlagConfig:
    """Configuration for a single feature flag scope."""
    
    # Identification
    scope_type: str  # "global", "organization", "project"
    scope_id: Optional[str] = None  # org ID or project ID
    
    # Scanning settings
    scanning_enabled: bool = True
    scanning_level: ScanningLevel = ScanningLevel.STANDARD
    action_on_detection: ActionOnDetection = ActionOnDetection.SANITIZE
    
    # Feature toggles
    scan_issues: bool = True
    scan_pull_requests: bool = True
    scan_comments: bool = True
    scan_file_contents: bool = True
    scan_commit_messages: bool = False  # Usually low risk
    
    # Detection toggles
    detect_credential_exfiltration: bool = True
    detect_action_steering: bool = True
    detect_system_prompt_extraction: bool = True
    detect_privilege_escalation: bool = True
    detect_data_exfiltration: bool = True
    
    # Layer toggles
    enable_trusted_filter: bool = True
    enable_data_filter: bool = True
    enable_detector: bool = True
    enable_prompt_fence: bool = True
    
    # Performance settings
    max_payload_size: int = 100000  # 100k characters
    timeout_ms: int = 5000  # 5 second timeout
    
    # Alerting
    alert_on_detection: bool = True
    alert_webhook_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scope_type": self.scope_type,
            "scope_id": self.scope_id,
            "scanning_enabled": self.scanning_enabled,
            "scanning_level": self.scanning_level.value,
            "action_on_detection": self.action_on_detection.value,
            "scan_issues": self.scan_issues,
            "scan_pull_requests": self.scan_pull_requests,
            "scan_comments": self.scan_comments,
            "scan_file_contents": self.scan_file_contents,
            "scan_commit_messages": self.scan_commit_messages,
            "detect_credential_exfiltration": self.detect_credential_exfiltration,
            "detect_action_steering": self.detect_action_steering,
            "detect_system_prompt_extraction": self.detect_system_prompt_extraction,
            "detect_privilege_escalation": self.detect_privilege_escalation,
            "detect_data_exfiltration": self.detect_data_exfiltration,
            "enable_trusted_filter": self.enable_trusted_filter,
            "enable_data_filter": self.enable_data_filter,
            "enable_detector": self.enable_detector,
            "enable_prompt_fence": self.enable_prompt_fence,
            "max_payload_size": self.max_payload_size,
            "timeout_ms": self.timeout_ms,
            "alert_on_detection": self.alert_on_detection,
            "alert_webhook_url": self.alert_webhook_url,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FeatureFlagConfig:
        """Create from dictionary."""
        return cls(
            scope_type=data.get("scope_type", "global"),
            scope_id=data.get("scope_id"),
            scanning_enabled=data.get("scanning_enabled", True),
            scanning_level=ScanningLevel(data.get("scanning_level", "standard")),
            action_on_detection=ActionOnDetection(data.get("action_on_detection", "sanitize")),
            scan_issues=data.get("scan_issues", True),
            scan_pull_requests=data.get("scan_pull_requests", True),
            scan_comments=data.get("scan_comments", True),
            scan_file_contents=data.get("scan_file_contents", True),
            scan_commit_messages=data.get("scan_commit_messages", False),
            detect_credential_exfiltration=data.get("detect_credential_exfiltration", True),
            detect_action_steering=data.get("detect_action_steering", True),
            detect_system_prompt_extraction=data.get("detect_system_prompt_extraction", True),
            detect_privilege_escalation=data.get("detect_privilege_escalation", True),
            detect_data_exfiltration=data.get("detect_data_exfiltration", True),
            enable_trusted_filter=data.get("enable_trusted_filter", True),
            enable_data_filter=data.get("enable_data_filter", True),
            enable_detector=data.get("enable_detector", True),
            enable_prompt_fence=data.get("enable_prompt_fence", True),
            max_payload_size=data.get("max_payload_size", 100000),
            timeout_ms=data.get("timeout_ms", 5000),
            alert_on_detection=data.get("alert_on_detection", True),
            alert_webhook_url=data.get("alert_webhook_url"),
        )


class FeatureFlags:
    """
    Feature flag manager for Prompt Shield.
    
    Supports hierarchical configuration:
    - Global defaults
    - Organization overrides
    - Project overrides
    
    More specific settings override less specific ones.
    """
    
    def __init__(self):
        self._global_config = FeatureFlagConfig(scope_type="global")
        self._org_configs: Dict[str, FeatureFlagConfig] = {}
        self._project_configs: Dict[str, FeatureFlagConfig] = {}
    
    def set_global_config(self, config: FeatureFlagConfig) -> None:
        """Set global configuration."""
        config.scope_type = "global"
        self._global_config = config
    
    def set_org_config(self, org_id: str, config: FeatureFlagConfig) -> None:
        """Set organization-level configuration."""
        config.scope_type = "organization"
        config.scope_id = org_id
        self._org_configs[org_id] = config
    
    def set_project_config(self, project_id: str, config: FeatureFlagConfig) -> None:
        """Set project-level configuration."""
        config.scope_type = "project"
        config.scope_id = project_id
        self._project_configs[project_id] = config
    
    def get_config(
        self,
        project_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> FeatureFlagConfig:
        """
        Get effective configuration for a given context.
        
        Priority: project > organization > global
        """
        # Start with global defaults
        effective = self._global_config
        
        # Apply organization overrides if available
        if org_id and org_id in self._org_configs:
            effective = self._merge_configs(effective, self._org_configs[org_id])
        
        # Apply project overrides if available
        if project_id and project_id in self._project_configs:
            effective = self._merge_configs(effective, self._project_configs[project_id])
        
        return effective
    
    def _merge_configs(
        self,
        base: FeatureFlagConfig,
        override: FeatureFlagConfig,
    ) -> FeatureFlagConfig:
        """Merge two configs, with override taking precedence."""
        # For simplicity, just return the override
        # In a full implementation, you might want field-by-field merging
        return override
    
    def is_scanning_enabled(
        self,
        project_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> bool:
        """Check if scanning is enabled for the given context."""
        config = self.get_config(project_id, org_id)
        return config.scanning_enabled
    
    def should_scan_content_type(
        self,
        content_type: str,
        project_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> bool:
        """Check if a specific content type should be scanned."""
        config = self.get_config(project_id, org_id)
        
        if not config.scanning_enabled:
            return False
        
        content_type_map = {
            "issue": config.scan_issues,
            "pull_request": config.scan_pull_requests,
            "comment": config.scan_comments,
            "file": config.scan_file_contents,
            "commit": config.scan_commit_messages,
        }
        
        return content_type_map.get(content_type, True)
    
    def export_config(self) -> Dict[str, Any]:
        """Export all configurations as JSON-serializable dict."""
        return {
            "global": self._global_config.to_dict(),
            "organizations": {
                org_id: config.to_dict()
                for org_id, config in self._org_configs.items()
            },
            "projects": {
                project_id: config.to_dict()
                for project_id, config in self._project_configs.items()
            },
        }
    
    def import_config(self, data: Dict[str, Any]) -> None:
        """Import configurations from dict."""
        if "global" in data:
            self._global_config = FeatureFlagConfig.from_dict(data["global"])
        
        if "organizations" in data:
            for org_id, config_data in data["organizations"].items():
                self._org_configs[org_id] = FeatureFlagConfig.from_dict(config_data)
        
        if "projects" in data:
            for project_id, config_data in data["projects"].items():
                self._project_configs[project_id] = FeatureFlagConfig.from_dict(config_data)
    
    def save_to_file(self, path: str) -> None:
        """Save configuration to JSON file."""
        with open(path, "w") as f:
            json.dump(self.export_config(), f, indent=2)
    
    def load_from_file(self, path: str) -> None:
        """Load configuration from JSON file."""
        with open(path, "r") as f:
            self.import_config(json.load(f))


# Convenience function for quick setup
def create_default_flags() -> FeatureFlags:
    """Create feature flags with sensible defaults."""
    flags = FeatureFlags()
    flags.set_global_config(FeatureFlagConfig(
        scope_type="global",
        scanning_enabled=True,
        scanning_level=ScanningLevel.STANDARD,
        action_on_detection=ActionOnDetection.SANITIZE,
    ))
    return flags
