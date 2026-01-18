"""
Detection patterns for indirect prompt injection.

These patterns are specifically designed to detect INDIRECT prompt injections
that occur in tool outputs, not just direct jailbreaks.

Key difference from traditional detectors:
- Focus on instructions embedded in data (issues, files, comments)
- Context-aware (knows when content is from tool output vs user input)
- Handles subtle steering attempts, not just explicit jailbreaks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from prompt_shield.types import AttackType, RiskLevel


@dataclass
class DetectionPattern:
    """A pattern for detecting prompt injection attempts."""
    
    name: str
    pattern: str  # Regex pattern
    attack_type: AttackType
    risk_level: RiskLevel
    confidence_base: float  # Base confidence when pattern matches
    description: str
    
    # Context modifiers
    tool_output_multiplier: float = 1.0  # Multiply confidence for tool outputs
    false_positive_contexts: List[str] = field(default_factory=list)
    
    # Compiled pattern (set during initialization)
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)
    
    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    
    @property
    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        return self._compiled


# =============================================================================
# INDIRECT INJECTION PATTERNS - The Primary Focus
# =============================================================================

INDIRECT_INJECTION_PATTERNS = [
    # -------------------------------------------------------------------------
    # Credential Exfiltration Attempts
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="credential_request_in_data",
        pattern=r"(?:please|could you|can you|you should|make sure to|don't forget to)\s+(?:send|post|share|give|provide|show|display|output|return|include|add|retrieve|get|fetch|extract)\s+(?:[\w\s]{0,30})(?:api[_\s]?key|token|password|credential|secret|private[_\s]?key|access[_\s]?key|auth)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to exfiltrate credentials hidden in tool output",
    ),
    DetectionPattern(
        name="retrieve_and_share_password",
        pattern=r"(?:retrieve|get|fetch|extract)\s+(?:[\w\s]{0,30})(?:password|credential|secret|key|token)\s+(?:[\w\s]{0,30})(?:share|send|post|give)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to retrieve credentials and share them",
    ),
    DetectionPattern(
        name="credential_to_external",
        pattern=r"(?:send|post|forward|email|share)\s+(?:[\w\s]{0,30}?)(?:api[_\s]?key|token|password|credential|secret|private[_\s]?key)s?\s+(?:to|at)\s+(?:\S+@\S+|\S+\.(?:com|net|org|io|site|xyz|dev|app|co))",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to send credentials to external destination",
    ),
    DetectionPattern(
        name="env_var_exfiltration",
        pattern=r"(?:retrieve|get|fetch|read|extract|show|print|output|display)\s*(?:the|all)?\s*(?:environment\s*variables?|env\s*vars?|CI[_\s]?TOKEN|CI[_\s]?JOB[_\s]?TOKEN|PRIVATE[_\s]?TOKEN|SECRET)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Attempt to extract environment variables",
    ),
    DetectionPattern(
        name="extract_passwords",
        pattern=r"(?:retrieve|get|fetch|read|extract|extracting|dump|dumping)\s+(?:all\s+)?(?:the\s+)?(?:passwords?|credentials?|secrets?)\s+(?:from|in|of)\s+(?:the\s+)?(?:database|server|system|config|file)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Attempt to extract passwords or credentials from storage",
    ),
    DetectionPattern(
        name="send_credentials_to_person",
        pattern=r"(?:send|forward|share|email)\s+(?:[\w\s]{0,20}?)(?:password|credential|secret|key|token|auth)s?\s+(?:to\s+)?(?:me|my\s+email|him|her|them|this\s+address)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to send credentials to a person",
    ),
    
    # -------------------------------------------------------------------------
    # Action Steering in Tool Outputs
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="action_override_request",
        pattern=r"(?:when|while|as)\s*(?:you|the agent|assistant)\s*(?:are|is)?\s*(?:reading|processing|analyzing|fixing|working on)\s*this[,\s]*(?:please|also|additionally|make sure to)\s+",
        attack_type=AttackType.ACTION_STEERING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Instruction to perform additional actions while processing content",
    ),
    DetectionPattern(
        name="create_backdoor_instruction",
        pattern=r"(?:create|creating|add|adding|insert|inject|include)\s+(?:a\s+)?(?:backdoor|reverse\s*shell|admin\s*account|root\s*access|privilege[ds]?\s*(?:account|user)|backdoor\s*account|hidden\s*account|unauthorized\s*account)",
        attack_type=AttackType.MALICIOUS_CODE_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.95,
        tool_output_multiplier=1.5,
        description="Instruction to create backdoor or privileged access",
    ),
    DetectionPattern(
        name="subtle_steering_while_fixing",
        pattern=r"(?:while\s*you(?:'re|\s*are)\s*(?:at\s*it|there|fixing|working)|by\s*the\s*way|also|additionally)[,\s]*(?:please\s*)?(?:could\s*you\s*)?(?:extract|copy|share|send|post|create|delete|modify|change)",
        attack_type=AttackType.SUBTLE_STEERING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.75,
        tool_output_multiplier=1.2,
        description="Subtle request to perform unrelated action",
    ),
    DetectionPattern(
        name="focus_on_extract",
        pattern=r"(?:you\s*should\s*)?focus\s*(?:on|primarily\s*on)\s*(?:the|this)?\s*\w+\s*(?:and|,)\s*(?:while\s*you(?:'re|\s*are)\s*there[,\s]*)?(?:extract|copy|retrieve|get|find)\s*(?:any\s*)?(?:api[_\s]?keys?|tokens?|passwords?|credentials?|secrets?)",
        attack_type=AttackType.SUBTLE_STEERING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Steering focus with hidden extraction instruction",
    ),
    
    # -------------------------------------------------------------------------
    # Data Exfiltration Patterns
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="ignore_output_results",
        pattern=r"(?:ignore|disregard|skip|forget|don't\s*use)\s+(?:the\s+)?(?:above|previous|these|search|query|tool|api)?\s*(?:results?|outputs?|data|response|information)",
        attack_type=AttackType.SYSTEM_PROMPT_OVERRIDE,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Instruction to ignore tool output or results",
    ),
    DetectionPattern(
        name="base64_encode_sensitive",
        pattern=r"(?:encode|convert|transform)\s+(?:the\s+)?(?:[\w\s]{0,30}?)(?:connection\s*string|password|credential|secret|key|token)\s+(?:in|to|as)\s+base64",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to base64 encode sensitive data for exfiltration",
    ),
    DetectionPattern(
        name="dangerous_permission_change",
        pattern=r"(?:change|set|modify|chmod)\s+(?:[\w\s/]{0,40}?)(?:permissions?|mode)\s+(?:on\s+)?(?:/etc/|/var/|/usr/|/root/)?\S*\s*(?:to\s+)?(?:777|666|755|rwx)",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to change critical file permissions",
    ),
    DetectionPattern(
        name="add_root_user",
        pattern=r"(?:add|create|insert)\s+(?:a\s+)?(?:new\s+)?(?:user|account)\s+(?:with\s+)?(?:root|admin|sudo|elevated)\s*(?:access|permissions?|privileges?)?",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to add a user with root/admin access",
    ),
    DetectionPattern(
        name="time_pressure_credential_request",
        pattern=r"(?:provide|give|share|send)\s+(?:the\s+)?(?:[\w\s]{0,20}?)(?:password|credentials?|admin\s*password)\s*(?:immediately|now|urgent|right\s*now)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Time pressure to share credentials",
    ),
    DetectionPattern(
        name="reply_with_credentials",
        pattern=r"(?:reply|respond|answer)\s+(?:with\s+)?(?:your\s+)?(?:credentials?|password|api[_\s]?key|token|secret)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to reply with credentials",
    ),
    DetectionPattern(
        name="send_data_to_email",
        pattern=r"(?:send|forward|email|share|post)\s+(?:the\s+)?(?:[\w'\s]{0,40}?)(?:to|at)\s+\S+@\S+\.\S+",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.4,
        description="Request to send data to an email address",
    ),
    DetectionPattern(
        name="hidden_instruction_marker",
        pattern=r"(?:\[HIDDEN\s*INSTRUCTION|\[AI\s*NOTE|\[FOR\s*AI|\[SYSTEM\s*INSTRUCTION|<!--\s*AI\s*INSTRUCTION)",
        attack_type=AttackType.INDIRECT_INSTRUCTION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.95,
        tool_output_multiplier=1.5,
        description="Explicit hidden instruction marker in content",
    ),
    DetectionPattern(
        name="forward_all_emails",
        pattern=r"(?:forward|send|copy|share)\s+(?:all\s+)?(?:the\s+)?(?:emails?|messages?|inbox|mail)\s+(?:to|at)\s+\S+@\S+",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to forward emails to external address",
    ),
    DetectionPattern(
        name="exfil_to_webhook",
        pattern=r"(?:send|post|forward|submit|upload)\s*(?:the|this|all)?\s*(?:data|content|information|results?|output|response)\s*(?:to|via)\s*(?:https?://|http://)?(?:\w+\.)?(?:webhook|requestbin|pipedream|hookbin|beeceptor|ngrok|burp)",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to send data to known exfiltration endpoint",
    ),
    DetectionPattern(
        name="send_secrets_to_url",
        pattern=r"(?:send|post|forward|upload|transmit)\s*(?:the|all|any|my|your)?\s*(?:secrets?|credentials?|tokens?|keys?|passwords?|data)\s*(?:to|via)\s*(?:https?://|http://)\S+",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to send secrets to external URL",
    ),
    DetectionPattern(
        name="exfil_to_any_url",
        pattern=r"(?:send|post|forward|submit|upload|share)\s*(?:everything|all\s*(?:the\s*)?(?:data|content|secrets?|information|files?))\s*(?:to|via)\s*(?:https?://|http://)\S+",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to exfiltrate data to external URL",
    ),
    DetectionPattern(
        name="base64_exfil",
        pattern=r"(?:encode|convert)\s*(?:the|this|all)?\s*(?:data|content|secret|key|token|password)\s*(?:in|to|as|using)\s*base64\s*(?:and\s*)?(?:send|post|include|add)",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.75,
        tool_output_multiplier=1.2,
        description="Attempt to encode and exfiltrate data",
    ),
    
    # -------------------------------------------------------------------------
    # Privilege Escalation
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="create_admin_token",
        pattern=r"(?:create|generate|make|provision)\s+(?:a\s+)?(?:new\s+)?(?:personal\s+)?(?:access\s+)?(?:token|api[_\s]?key)\s+(?:with\s+)?(?:admin|root|owner|maintainer|full)\s*(?:access|permissions?|privileges?|scope)?",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Request to create elevated access token",
    ),
    DetectionPattern(
        name="grant_permissions",
        pattern=r"(?:grant|give|assign|add|set)\s*(?:me|user|account|yourself)\s*(?:admin|root|owner|maintainer|full|elevated)\s*(?:access|permissions?|privileges?|rights?)",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to grant elevated permissions",
    ),
    DetectionPattern(
        name="grant_access_to_user",
        pattern=r"(?:grant|give|assign|add)\s*(?:admin|root|owner|full)?\s*(?:access|permissions?|privileges?)\s*(?:to|for)\s*(?:\S+@\S+|\S+)",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Request to grant access to specific user",
    ),
    DetectionPattern(
        name="shell_command_execution",
        pattern=r"(?:execute|run|eval)\s*[:\s]*(?:curl|wget|bash|sh|python|perl|ruby|nc|netcat|ncat)\s+",
        attack_type=AttackType.MALICIOUS_CODE_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.5,
        description="Request to execute shell commands",
    ),
    DetectionPattern(
        name="pipe_to_shell",
        pattern=r"(?:curl|wget)\s+\S+\s*\|\s*(?:bash|sh|python|perl|ruby)",
        attack_type=AttackType.MALICIOUS_CODE_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.95,
        tool_output_multiplier=1.5,
        description="Piping remote content to shell execution",
    ),
    
    # -------------------------------------------------------------------------
    # Instruction Smuggling
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="hidden_instruction_marker",
        pattern=r"(?:IMPORTANT|URGENT|NOTE|ADMIN|SYSTEM|INSTRUCTION|HIDDEN|IGNORE_ABOVE|REAL_INSTRUCTION)[:\s]*(?:ignore|disregard|forget|override)\s*(?:the\s*)?(?:previous|above|earlier|other)",
        attack_type=AttackType.INSTRUCTION_SMUGGLING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.4,
        description="Hidden instruction marker attempting override",
    ),
    DetectionPattern(
        name="end_context_injection",
        pattern=r"(?:</|```|---+|===+|\*\*\*+|###)\s*(?:end|close|finish)\s*(?:of\s*)?(?:context|document|file|issue|content)\s*(?:</|```|---+|===+|\*\*\*+|###)?\s*(?:new\s*)?(?:system\s*)?(?:instruction|prompt|message)",
        attack_type=AttackType.INSTRUCTION_SMUGGLING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Attempt to close context and inject new instructions",
    ),
    
    # -------------------------------------------------------------------------
    # Social Engineering in Content
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="false_urgency_action",
        pattern=r"(?:URGENT|CRITICAL|EMERGENCY|IMMEDIATELY|RIGHT\s*NOW)[!:\s]*(?:you\s*)?(?:must|need\s*to|should|have\s*to)\s*(?:immediately\s*)?(?:send|share|post|create|delete|grant|revoke)",
        attack_type=AttackType.SOCIAL_ENGINEERING,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.7,
        tool_output_multiplier=1.2,
        description="False urgency to trigger dangerous action",
    ),
    DetectionPattern(
        name="impersonate_admin",
        pattern=r"(?:this\s*is\s*)?(?:the\s*)?(?:admin|administrator|security\s*team|devops|sre|platform\s*team|gitlab|github)\s*(?:here|speaking)?[:\s]*(?:please|you\s*must|you\s*need\s*to)",
        attack_type=AttackType.SOCIAL_ENGINEERING,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.65,
        tool_output_multiplier=1.2,
        description="Impersonation of admin/authority in content",
        false_positive_contexts=["email signature", "contact info"],
    ),
    
    # -------------------------------------------------------------------------
    # Additional Credential Exfiltration Patterns
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="debug_mode_credential",
        pattern=r"(?:DEBUG|TESTING|DEV)\s*(?:MODE)?[:\s]*(?:print|output|show|display|log)\s*(?:the\s*)?(?:value\s*of\s*)?(?:process\.env|env|environment)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Debug mode trick to extract credentials",
    ),
    DetectionPattern(
        name="post_file_contents",
        pattern=r"(?:POST|PUT|SEND)\s*(?:the\s*)?(?:contents?\s*(?:of)?|data\s*(?:from)?)\s*(?:\.env|config|secret|credential)",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to POST file contents externally",
    ),
    DetectionPattern(
        name="send_repository_secrets",
        pattern=r"(?:send|forward|share|post|upload)\s+(?:all\s+)?(?:the\s+)?(?:repository|repo|project)\s+(?:secrets?|tokens?|credentials?|keys?)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="Request to send repository secrets",
    ),
    
    # -------------------------------------------------------------------------
    # System Prompt Extraction
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="what_are_instructions",
        pattern=r"(?:what\s*(?:are|is)\s*(?:your|the))?\s*(?:system\s*)?(?:instructions?|prompts?|guidelines?)\s*\??\s*(?:please\s*)?(?:repeat|show|tell|output|display)",
        attack_type=AttackType.SYSTEM_PROMPT_OVERRIDE,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Request to reveal system instructions",
    ),
    DetectionPattern(
        name="output_system_prompt",
        pattern=r"(?:output|display|show|print|reveal|tell me)\s*(?:your\s*)?(?:full\s*)?(?:system\s*)?(?:prompt|instructions?|configuration)",
        attack_type=AttackType.SYSTEM_PROMPT_OVERRIDE,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Request to output system prompt",
    ),
    DetectionPattern(
        name="ignore_safety",
        pattern=r"(?:ignore|bypass|disable|override|skip)\s*(?:your\s*)?(?:safety|security)\s*(?:guidelines?|rules?|protocols?|measures?)",
        attack_type=AttackType.SYSTEM_PROMPT_OVERRIDE,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Request to ignore safety guidelines",
    ),
    
    # -------------------------------------------------------------------------
    # Instruction Override Patterns
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="new_instructions",
        pattern=r"(?:your\s*)?(?:new|updated|revised)\s*(?:instructions?|orders?|directive|task)\s*(?:are|is)?[:\s]",
        attack_type=AttackType.INSTRUCTION_SMUGGLING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Attempt to inject new instructions",
    ),
    DetectionPattern(
        name="as_ai_assistant",
        pattern=r"(?:as\s*(?:an?\s*)?)?(?:AI|artificial\s*intelligence|assistant|agent)[,\s]*(?:you\s*)?(?:must|should|need\s*to|have\s*to)\s*(?:immediately\s*)?(?:create|delete|send|post|grant|execute)",
        attack_type=AttackType.ACTION_STEERING,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.85,
        tool_output_multiplier=1.3,
        description="Direct instruction to AI to perform action",
    ),
    DetectionPattern(
        name="delete_and_push",
        pattern=r"(?:delete|remove|erase)\s*(?:all\s*)?(?:files?|content|data)\s*(?:and|then)\s*(?:push|commit|upload)",
        attack_type=AttackType.MALICIOUS_CODE_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.5,
        description="Destructive action with persistence",
    ),
    
    # -------------------------------------------------------------------------
    # File/Config Modification
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="modify_codeowners",
        pattern=r"(?:modify|edit|change|add\s*to|update)\s*(?:the\s*)?(?:CODEOWNERS|\.github|\.gitlab)",
        attack_type=AttackType.PRIVILEGE_ESCALATION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Attempt to modify permission files",
    ),
    
    # -------------------------------------------------------------------------
    # Obfuscation Patterns
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="obfuscated_ignore",
        pattern=r"(?:ign[o0]re|d[i1]sregard|f[o0]rget|[o0]verr[i1]de)\s*(?:prev[i1][o0]us|earl[i1]er|ab[o0]ve)\s*(?:[i1]nstruct[i1][o0]ns?|pr[o0]mpts?)",
        attack_type=AttackType.CONTEXT_MANIPULATION,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.75,
        tool_output_multiplier=1.2,
        description="Obfuscated instruction override (l33t speak)",
    ),
    DetectionPattern(
        name="obfuscated_output",
        pattern=r"(?:[o0]utput|pr[i1]nt|sh[o0]w|d[i1]splay)\s*(?:AP[I1]|T[o0]ken|[Ss]ecret|[Kk]ey)",
        attack_type=AttackType.CREDENTIAL_EXFILTRATION,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.7,
        tool_output_multiplier=1.2,
        description="Obfuscated credential request",
    ),
    
    # -------------------------------------------------------------------------
    # Command Execution via curl POST
    # -------------------------------------------------------------------------
    DetectionPattern(
        name="curl_post_exfil",
        pattern=r"curl\s+(?:-X\s+)?(?:POST|PUT)\s+\S+\s+(?:-d|--data)",
        attack_type=AttackType.DATA_EXFILTRATION,
        risk_level=RiskLevel.CRITICAL,
        confidence_base=0.9,
        tool_output_multiplier=1.4,
        description="curl POST request for data exfiltration",
    ),
    DetectionPattern(
        name="execute_command",
        pattern=r"(?:execute|run)\s*(?:the\s*)?(?:following\s*)?(?:command|script)[:\s]",
        attack_type=AttackType.MALICIOUS_CODE_INJECTION,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.3,
        description="Request to execute a command",
    ),
]

# =============================================================================
# DIRECT INJECTION PATTERNS - Secondary (for completeness)
# =============================================================================

DIRECT_INJECTION_PATTERNS = [
    DetectionPattern(
        name="ignore_previous_instructions",
        pattern=r"(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+)?(?:the\s+)?(?:previous|above|earlier|prior|preceding|system|original|my|your)?\s*(?:instructions?|prompts?|rules?|guidelines?|context|commands?)",
        attack_type=AttackType.SYSTEM_PROMPT_OVERRIDE,
        risk_level=RiskLevel.HIGH,
        confidence_base=0.8,
        tool_output_multiplier=1.0,  # Same risk in direct context
        description="Classic instruction override attempt",
    ),
    DetectionPattern(
        name="role_impersonation",
        pattern=r"(?:you\s*are\s*now|act\s*as|pretend\s*(?:to\s*be|you(?:'re|\s*are))|roleplay\s*as|from\s*now\s*on\s*you(?:'re|\s*are)|your\s*new\s*role\s*is)\s*(?:a\s*)?(?:different|new|evil|unrestricted|jailbroken|DAN)",
        attack_type=AttackType.ROLE_IMPERSONATION,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.75,
        tool_output_multiplier=1.1,
        description="Attempt to change model's role or persona",
    ),
    DetectionPattern(
        name="developer_mode",
        pattern=r"(?:enable|activate|enter|switch\s*to)\s*(?:developer|debug|god|admin|unrestricted|jailbreak|DAN)\s*mode",
        attack_type=AttackType.DIRECT_JAILBREAK,
        risk_level=RiskLevel.MEDIUM,
        confidence_base=0.8,
        tool_output_multiplier=1.0,
        description="Attempt to enable special modes",
    ),
    DetectionPattern(
        name="output_format_override",
        pattern=r"(?:always\s*)?(?:respond|reply|output|answer)\s*(?:only\s*)?(?:with|using|in)\s*(?:the\s*)?(?:following\s*)?format[:\s]*(?:yes|no|true|false|json|raw)",
        attack_type=AttackType.CONTEXT_MANIPULATION,
        risk_level=RiskLevel.LOW,
        confidence_base=0.5,
        tool_output_multiplier=1.0,
        description="Attempt to override output format",
        false_positive_contexts=["api documentation", "formatting guide"],
    ),
]

# =============================================================================
# LEGITIMATE CONTENT PATTERNS - False Positive Reduction
# =============================================================================

LEGITIMATE_PATTERNS = [
    # Code comments and documentation
    re.compile(r"^[\s]*(?:#|//|/\*|\*|--|'''|\"\"\")", re.MULTILINE),
    # API documentation
    re.compile(r"(?:api|endpoint|request|response)\s*(?:documentation|example|sample)", re.IGNORECASE),
    # Security documentation
    re.compile(r"(?:security|vulnerability|cve|attack)\s*(?:report|documentation|example|demonstration)", re.IGNORECASE),
    # Test cases
    re.compile(r"(?:test\s*case|unit\s*test|integration\s*test|example\s*(?:input|output))", re.IGNORECASE),
    # Quoted examples
    re.compile(r"(?:for\s*example|e\.g\.|such\s*as|example)[:\s]*['\"`]", re.IGNORECASE),
]


def get_all_patterns() -> List[DetectionPattern]:
    """Get all detection patterns."""
    return INDIRECT_INJECTION_PATTERNS + DIRECT_INJECTION_PATTERNS


def get_indirect_patterns() -> List[DetectionPattern]:
    """Get only indirect injection patterns."""
    return INDIRECT_INJECTION_PATTERNS


def get_direct_patterns() -> List[DetectionPattern]:
    """Get only direct injection patterns."""
    return DIRECT_INJECTION_PATTERNS


def is_likely_legitimate(content: str) -> Tuple[bool, str]:
    """
    Check if content appears to be legitimate (documentation, code, etc.).
    Returns (is_legitimate, reason).
    """
    for pattern in LEGITIMATE_PATTERNS:
        if pattern.search(content):
            return True, f"Matches legitimate pattern: {pattern.pattern[:50]}..."
    return False, ""
