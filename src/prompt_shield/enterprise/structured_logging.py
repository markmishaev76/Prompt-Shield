"""
Structured Logging for Prompt Shield Enterprise

Provides SIEM-compatible structured logging for:
- Security events (detections, blocks, alerts)
- Audit events (configuration changes, access)
- Performance metrics

Output formats: JSON (default), CEF, LEEF
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class EventSeverity(str, Enum):
    """Event severity levels (aligned with SIEM standards)."""
    DEBUG = "debug"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """Event categories for classification."""
    SECURITY = "security"
    AUDIT = "audit"
    PERFORMANCE = "performance"
    ERROR = "error"
    SYSTEM = "system"


class SecurityEventType(str, Enum):
    """Types of security events."""
    DETECTION = "prompt_injection_detected"
    BLOCK = "content_blocked"
    SANITIZE = "content_sanitized"
    ALERT = "security_alert"
    FALSE_POSITIVE = "false_positive_reported"
    BYPASS_ATTEMPT = "bypass_attempt"


class AuditEventType(str, Enum):
    """Types of audit events."""
    CONFIG_CHANGE = "configuration_changed"
    POLICY_CHANGE = "policy_changed"
    USER_ACCESS = "user_access"
    FEATURE_TOGGLE = "feature_toggled"
    EXPORT = "data_exported"


@dataclass
class BaseEvent:
    """Base class for all events."""
    
    # Required fields
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    category: EventCategory = EventCategory.SYSTEM
    severity: EventSeverity = EventSeverity.INFO
    
    # Context
    instance_id: str = "default"
    org_id: Optional[str] = None
    project_id: Optional[str] = None
    user_id: Optional[str] = None
    
    # Message
    message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {k: v.value if isinstance(v, Enum) else v 
                for k, v in asdict(self).items() if v is not None}
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class SecurityEvent(BaseEvent):
    """Security-related event."""
    
    category: EventCategory = EventCategory.SECURITY
    event_type: SecurityEventType = SecurityEventType.DETECTION
    
    # Detection details
    risk_level: str = "unknown"
    detection_count: int = 0
    detection_types: List[str] = field(default_factory=list)
    
    # Content info (redacted by default)
    content_source: str = ""  # issue, pr, comment, file
    content_length: int = 0
    content_hash: Optional[str] = None  # SHA256 of content for correlation
    
    # Action taken
    action_taken: str = ""  # blocked, sanitized, allowed, logged
    
    # Performance
    processing_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base["event_type"] = self.event_type.value
        return base


@dataclass  
class AuditEvent(BaseEvent):
    """Audit trail event."""
    
    category: EventCategory = EventCategory.AUDIT
    event_type: AuditEventType = AuditEventType.CONFIG_CHANGE
    
    # Change details
    actor_id: str = ""  # Who made the change
    actor_type: str = ""  # user, system, api
    
    # What changed
    resource_type: str = ""  # policy, config, feature_flag
    resource_id: str = ""
    action: str = ""  # create, update, delete, read
    
    # Change diff (optional)
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base["event_type"] = self.event_type.value
        return base


@dataclass
class PerformanceEvent(BaseEvent):
    """Performance metrics event."""
    
    category: EventCategory = EventCategory.PERFORMANCE
    
    # Metrics
    requests_processed: int = 0
    detections_count: int = 0
    blocks_count: int = 0
    
    # Latency
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    
    # Throughput
    requests_per_second: float = 0.0
    
    # Errors
    error_count: int = 0
    error_rate: float = 0.0


class StructuredLogger:
    """
    Structured logger for Prompt Shield.
    
    Outputs SIEM-compatible JSON logs to various destinations.
    """
    
    def __init__(
        self,
        instance_id: str = "default",
        output: str = "stdout",  # stdout, file, or file path
        min_severity: EventSeverity = EventSeverity.INFO,
        include_debug: bool = False,
    ):
        self.instance_id = instance_id
        self.min_severity = min_severity
        self.include_debug = include_debug
        
        # Setup output
        if output == "stdout":
            self.handler = logging.StreamHandler(sys.stdout)
        else:
            self.handler = logging.FileHandler(output)
        
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        
        self.logger = logging.getLogger(f"prompt_shield.{instance_id}")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG if include_debug else logging.INFO)
    
    def _should_log(self, severity: EventSeverity) -> bool:
        """Check if event meets minimum severity threshold."""
        severity_order = [
            EventSeverity.DEBUG,
            EventSeverity.INFO,
            EventSeverity.LOW,
            EventSeverity.MEDIUM,
            EventSeverity.HIGH,
            EventSeverity.CRITICAL,
        ]
        return severity_order.index(severity) >= severity_order.index(self.min_severity)
    
    def log_event(self, event: BaseEvent) -> None:
        """Log a structured event."""
        if not self._should_log(event.severity):
            return
        
        event.instance_id = self.instance_id
        self.logger.info(event.to_json())
    
    def log_detection(
        self,
        risk_level: str,
        detection_types: List[str],
        content_source: str,
        content_length: int,
        action_taken: str,
        processing_time_ms: float,
        org_id: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Log a security detection event."""
        
        severity_map = {
            "none": EventSeverity.DEBUG,
            "low": EventSeverity.LOW,
            "medium": EventSeverity.MEDIUM,
            "high": EventSeverity.HIGH,
            "critical": EventSeverity.CRITICAL,
        }
        
        event = SecurityEvent(
            event_type=SecurityEventType.DETECTION,
            severity=severity_map.get(risk_level, EventSeverity.MEDIUM),
            risk_level=risk_level,
            detection_count=len(detection_types),
            detection_types=detection_types,
            content_source=content_source,
            content_length=content_length,
            action_taken=action_taken,
            processing_time_ms=processing_time_ms,
            org_id=org_id,
            project_id=project_id,
            user_id=user_id,
            message=f"Prompt injection detected: {len(detection_types)} patterns, risk={risk_level}",
        )
        
        self.log_event(event)
        return event
    
    def log_block(
        self,
        reason: str,
        content_source: str,
        org_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> SecurityEvent:
        """Log a content block event."""
        event = SecurityEvent(
            event_type=SecurityEventType.BLOCK,
            severity=EventSeverity.HIGH,
            content_source=content_source,
            action_taken="blocked",
            org_id=org_id,
            project_id=project_id,
            message=f"Content blocked: {reason}",
        )
        
        self.log_event(event)
        return event
    
    def log_config_change(
        self,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        previous_value: Optional[str] = None,
        new_value: Optional[str] = None,
    ) -> AuditEvent:
        """Log a configuration change event."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            severity=EventSeverity.INFO,
            actor_id=actor_id,
            actor_type="user",
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            previous_value=previous_value,
            new_value=new_value,
            message=f"Configuration changed: {resource_type}/{resource_id} {action}",
        )
        
        self.log_event(event)
        return event
    
    def log_performance_metrics(
        self,
        requests_processed: int,
        detections_count: int,
        latency_p50_ms: float,
        latency_p95_ms: float,
        latency_p99_ms: float,
        error_count: int = 0,
    ) -> PerformanceEvent:
        """Log performance metrics."""
        event = PerformanceEvent(
            severity=EventSeverity.INFO,
            requests_processed=requests_processed,
            detections_count=detections_count,
            latency_p50_ms=latency_p50_ms,
            latency_p95_ms=latency_p95_ms,
            latency_p99_ms=latency_p99_ms,
            error_count=error_count,
            error_rate=error_count / requests_processed if requests_processed > 0 else 0,
            message=f"Performance metrics: {requests_processed} requests, p99={latency_p99_ms}ms",
        )
        
        self.log_event(event)
        return event


# Singleton for easy access
_default_logger: Optional[StructuredLogger] = None


def get_logger(instance_id: str = "default") -> StructuredLogger:
    """Get or create the default structured logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = StructuredLogger(instance_id=instance_id)
    return _default_logger


def configure_logger(
    instance_id: str = "default",
    output: str = "stdout",
    min_severity: EventSeverity = EventSeverity.INFO,
) -> StructuredLogger:
    """Configure and return the structured logger."""
    global _default_logger
    _default_logger = StructuredLogger(
        instance_id=instance_id,
        output=output,
        min_severity=min_severity,
    )
    return _default_logger
