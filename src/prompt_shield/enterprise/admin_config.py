"""
Admin Configuration for Prompt Shield Enterprise

Provides administrative settings for:
- Scanning policies
- Alerting configuration
- User/role management
- Compliance settings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


class RiskThreshold(str, Enum):
    """Risk thresholds for alerting."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(str, Enum):
    """Notification channels for alerts."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    SIEM = "siem"


@dataclass
class AlertingConfig:
    """Configuration for alerting and notifications."""
    
    enabled: bool = True
    min_risk_level: RiskThreshold = RiskThreshold.MEDIUM
    
    # Notification channels
    channels: List[NotificationChannel] = field(default_factory=list)
    
    # Channel-specific settings
    email_recipients: List[str] = field(default_factory=list)
    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    webhook_url: Optional[str] = None
    webhook_headers: Dict[str, str] = field(default_factory=dict)
    pagerduty_key: Optional[str] = None
    siem_endpoint: Optional[str] = None
    
    # Alert settings
    aggregate_alerts: bool = True  # Combine multiple alerts into one
    aggregation_window_seconds: int = 300  # 5 minutes
    max_alerts_per_hour: int = 100  # Rate limiting
    include_payload_sample: bool = False  # Privacy consideration
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "min_risk_level": self.min_risk_level.value,
            "channels": [c.value for c in self.channels],
            "email_recipients": self.email_recipients,
            "slack_webhook_url": self.slack_webhook_url,
            "slack_channel": self.slack_channel,
            "webhook_url": self.webhook_url,
            "webhook_headers": self.webhook_headers,
            "pagerduty_key": "***" if self.pagerduty_key else None,
            "siem_endpoint": self.siem_endpoint,
            "aggregate_alerts": self.aggregate_alerts,
            "aggregation_window_seconds": self.aggregation_window_seconds,
            "max_alerts_per_hour": self.max_alerts_per_hour,
            "include_payload_sample": self.include_payload_sample,
        }


@dataclass
class ScanningPolicy:
    """Scanning policy configuration."""
    
    name: str
    description: str = ""
    
    # Content rules
    max_content_length: int = 100000  # 100k characters
    allowed_content_types: List[str] = field(default_factory=lambda: [
        "issue", "pull_request", "comment", "file"
    ])
    
    # Detection rules
    enabled_detectors: List[str] = field(default_factory=lambda: [
        "credential_exfiltration",
        "action_steering", 
        "system_prompt_extraction",
        "privilege_escalation",
        "data_exfiltration",
    ])
    
    # Custom patterns (for organization-specific threats)
    custom_block_patterns: List[str] = field(default_factory=list)
    custom_allow_patterns: List[str] = field(default_factory=list)
    
    # Trusted sources (bypass scanning)
    trusted_users: List[str] = field(default_factory=list)
    trusted_domains: List[str] = field(default_factory=list)
    
    # Actions
    block_on_detection: bool = False  # Default to sanitize
    quarantine_suspicious: bool = True
    require_review_for_high_risk: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "max_content_length": self.max_content_length,
            "allowed_content_types": self.allowed_content_types,
            "enabled_detectors": self.enabled_detectors,
            "custom_block_patterns": self.custom_block_patterns,
            "custom_allow_patterns": self.custom_allow_patterns,
            "trusted_users": self.trusted_users,
            "trusted_domains": self.trusted_domains,
            "block_on_detection": self.block_on_detection,
            "quarantine_suspicious": self.quarantine_suspicious,
            "require_review_for_high_risk": self.require_review_for_high_risk,
        }


@dataclass
class ComplianceConfig:
    """Compliance and audit configuration."""
    
    # Data retention
    log_retention_days: int = 90
    audit_log_retention_days: int = 365
    
    # Privacy
    anonymize_user_data: bool = False
    redact_sensitive_content: bool = True
    gdpr_compliant: bool = True
    
    # Audit
    enable_audit_logging: bool = True
    log_all_requests: bool = False  # Only log detections by default
    log_full_payloads: bool = False  # Privacy consideration
    
    # Compliance frameworks
    soc2_mode: bool = False
    hipaa_mode: bool = False
    pci_mode: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_retention_days": self.log_retention_days,
            "audit_log_retention_days": self.audit_log_retention_days,
            "anonymize_user_data": self.anonymize_user_data,
            "redact_sensitive_content": self.redact_sensitive_content,
            "gdpr_compliant": self.gdpr_compliant,
            "enable_audit_logging": self.enable_audit_logging,
            "log_all_requests": self.log_all_requests,
            "log_full_payloads": self.log_full_payloads,
            "soc2_mode": self.soc2_mode,
            "hipaa_mode": self.hipaa_mode,
            "pci_mode": self.pci_mode,
        }


@dataclass
class AdminConfig:
    """
    Master admin configuration for Prompt Shield Enterprise.
    
    Combines all administrative settings into a single configuration.
    """
    
    # Instance identification
    instance_id: str = "default"
    instance_name: str = "Prompt Shield"
    
    # Policies
    default_policy: ScanningPolicy = field(default_factory=lambda: ScanningPolicy(name="default"))
    policies: Dict[str, ScanningPolicy] = field(default_factory=dict)
    
    # Alerting
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    
    # Compliance
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    
    # Performance
    max_concurrent_scans: int = 100
    request_timeout_ms: int = 5000
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    
    # Maintenance
    maintenance_mode: bool = False
    maintenance_message: str = ""
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0.0"
    
    def get_policy(self, policy_name: str) -> ScanningPolicy:
        """Get a scanning policy by name."""
        if policy_name in self.policies:
            return self.policies[policy_name]
        return self.default_policy
    
    def add_policy(self, policy: ScanningPolicy) -> None:
        """Add a scanning policy."""
        self.policies[policy.name] = policy
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "instance_id": self.instance_id,
            "instance_name": self.instance_name,
            "default_policy": self.default_policy.to_dict(),
            "policies": {name: p.to_dict() for name, p in self.policies.items()},
            "alerting": self.alerting.to_dict(),
            "compliance": self.compliance.to_dict(),
            "max_concurrent_scans": self.max_concurrent_scans,
            "request_timeout_ms": self.request_timeout_ms,
            "enable_caching": self.enable_caching,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "maintenance_mode": self.maintenance_mode,
            "maintenance_message": self.maintenance_message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }
    
    def save_to_file(self, path: str) -> None:
        """Save configuration to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, path: str) -> AdminConfig:
        """Load configuration from JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        
        # Reconstruct the config
        config = cls(
            instance_id=data.get("instance_id", "default"),
            instance_name=data.get("instance_name", "Prompt Shield"),
        )
        
        # Load other fields...
        # (Full implementation would parse all nested objects)
        
        return config


# Factory functions
def create_enterprise_config(
    instance_name: str,
    admin_emails: List[str],
    slack_webhook: Optional[str] = None,
) -> AdminConfig:
    """Create enterprise configuration with common settings."""
    
    alerting = AlertingConfig(
        enabled=True,
        min_risk_level=RiskThreshold.MEDIUM,
        channels=[NotificationChannel.EMAIL],
        email_recipients=admin_emails,
    )
    
    if slack_webhook:
        alerting.channels.append(NotificationChannel.SLACK)
        alerting.slack_webhook_url = slack_webhook
    
    compliance = ComplianceConfig(
        enable_audit_logging=True,
        gdpr_compliant=True,
        log_retention_days=90,
    )
    
    return AdminConfig(
        instance_name=instance_name,
        alerting=alerting,
        compliance=compliance,
    )


def create_strict_policy(name: str = "strict") -> ScanningPolicy:
    """Create a strict scanning policy."""
    return ScanningPolicy(
        name=name,
        description="Strict policy - blocks all detected threats",
        block_on_detection=True,
        quarantine_suspicious=True,
        require_review_for_high_risk=True,
    )


def create_permissive_policy(name: str = "permissive") -> ScanningPolicy:
    """Create a permissive scanning policy."""
    return ScanningPolicy(
        name=name,
        description="Permissive policy - logs only, no blocking",
        block_on_detection=False,
        quarantine_suspicious=False,
        require_review_for_high_risk=False,
    )
