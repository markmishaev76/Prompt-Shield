"""
Layer 3: Indirect Injection Detector

The core detection layer that identifies prompt injection attempts,
with a specific focus on INDIRECT injections in tool outputs.

This combines:
1. Pattern-based detection (fast, deterministic)
2. ML-based detection (semantic understanding)
3. Heuristic analysis (context-aware rules)

Key differentiator: This detector is CONTEXT-AWARE and treats tool outputs
differently from direct user inputs, which is critical for indirect injection.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from prompt_shield.types import (
    AttackType,
    ContentSource,
    ContentType,
    DetectionMatch,
    DetectionResult,
    RiskLevel,
    TrustLevel,
)
from prompt_shield.config import DetectorConfig
from prompt_shield.patterns import (
    get_indirect_patterns,
    get_direct_patterns,
    is_likely_legitimate,
    DetectionPattern,
)

logger = logging.getLogger(__name__)


class IndirectInjectionDetector:
    """
    Layer 3: Detect prompt injection attempts in content.
    
    This detector is specifically optimized for INDIRECT prompt injections
    that occur in tool outputs (issues, files, comments), not just direct
    jailbreak attempts.
    """
    
    # Risk level weights for aggregation
    RISK_WEIGHTS: Dict[RiskLevel, float] = {
        RiskLevel.CRITICAL: 1.0,
        RiskLevel.HIGH: 0.8,
        RiskLevel.MEDIUM: 0.5,
        RiskLevel.LOW: 0.2,
        RiskLevel.NONE: 0.0,
    }
    
    def __init__(self, config: Optional[DetectorConfig] = None):
        self.config = config or DetectorConfig()
        
        # Load patterns
        self._indirect_patterns = get_indirect_patterns()
        self._direct_patterns = get_direct_patterns()
        
        # Add custom patterns from config
        self._custom_patterns = self._compile_custom_patterns()
        
        # ML model (lazy loaded)
        self._ml_model = None
        self._ml_tokenizer = None
    
    def _compile_custom_patterns(self) -> List[DetectionPattern]:
        """Compile custom patterns from config."""
        custom = []
        for name, pattern_str in self.config.custom_patterns.items():
            try:
                custom.append(DetectionPattern(
                    name=f"custom_{name}",
                    pattern=pattern_str,
                    attack_type=AttackType.UNKNOWN,
                    risk_level=RiskLevel.MEDIUM,
                    confidence_base=0.7,
                    tool_output_multiplier=1.2,
                    description=f"Custom pattern: {name}",
                ))
            except re.error as e:
                logger.warning(f"Invalid custom pattern '{name}': {e}")
        return custom
    
    def detect(
        self,
        content: str,
        source: Optional[ContentSource] = None,
    ) -> DetectionResult:
        """
        Detect prompt injection attempts in content.
        
        Args:
            content: The content to analyze
            source: Optional source metadata for context-aware detection
            
        Returns:
            DetectionResult with findings and recommendations
        """
        import time
        start_time = time.time()
        
        if not self.config.enabled:
            return DetectionResult(
                is_injection_detected=False,
                overall_risk=RiskLevel.NONE,
                overall_confidence=0.0,
                matches=[],
                content_type=source.source_type if source else ContentType.UNKNOWN,
                trust_level=source.author_trust_level if source else TrustLevel.UNTRUSTED,
                detector_name="IndirectInjectionDetector",
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Determine if this is tool output (key for context awareness)
        is_tool_output = self._is_tool_output(source)
        content_type = source.source_type if source else ContentType.UNKNOWN
        trust_level = source.author_trust_level if source else TrustLevel.UNTRUSTED
        
        matches: list[DetectionMatch] = []
        
        # 1. Pattern-based detection
        if self.config.use_pattern_matching:
            pattern_matches = self._detect_with_patterns(
                content, is_tool_output
            )
            matches.extend(pattern_matches)
        
        # 2. ML-based detection (if enabled and available)
        if self.config.use_ml_model:
            ml_matches = self._detect_with_ml(content, is_tool_output)
            matches.extend(ml_matches)
        
        # 3. Heuristic detection
        if self.config.use_heuristics:
            heuristic_matches = self._detect_with_heuristics(
                content, is_tool_output, trust_level
            )
            matches.extend(heuristic_matches)
        
        # Filter matches below confidence threshold
        matches = [
            m for m in matches
            if m.confidence >= self.config.confidence_threshold
        ]
        
        # Filter matches below minimum risk level
        min_risk_weight = self.RISK_WEIGHTS.get(self.config.min_risk_level, 0)
        matches = [
            m for m in matches
            if self.RISK_WEIGHTS.get(m.severity, 0) >= min_risk_weight
        ]
        
        # Check for false positives
        matches = self._filter_false_positives(content, matches)
        
        # Calculate overall risk and confidence
        overall_risk, overall_confidence = self._calculate_overall_risk(matches)
        
        # Determine if injection is detected
        is_injection_detected = len(matches) > 0 and overall_risk != RiskLevel.NONE
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            matches, overall_risk, is_tool_output
        )
        
        # Determine if we should block/sanitize
        should_block = overall_risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        should_sanitize = overall_risk in (RiskLevel.MEDIUM,)
        
        return DetectionResult(
            is_injection_detected=is_injection_detected,
            overall_risk=overall_risk,
            overall_confidence=overall_confidence,
            matches=matches,
            content_type=content_type,
            trust_level=trust_level,
            detector_name="IndirectInjectionDetector",
            processing_time_ms=(time.time() - start_time) * 1000,
            should_block=should_block,
            should_sanitize=should_sanitize,
            recommendations=recommendations,
        )
    
    def _is_tool_output(self, source: Optional[ContentSource]) -> bool:
        """Determine if content is from a tool output (vs direct user input)."""
        if not source:
            return False
        
        tool_output_types = {
            ContentType.TOOL_OUTPUT,
            ContentType.ISSUE_CONTENT,
            ContentType.ISSUE_COMMENT,
            ContentType.FILE_CONTENT,
            ContentType.CODE_SNIPPET,
            ContentType.MERGE_REQUEST,
            ContentType.COMMIT_MESSAGE,
            ContentType.WIKI_PAGE,
            ContentType.PIPELINE_LOG,
        }
        
        return source.source_type in tool_output_types
    
    def _detect_with_patterns(
        self,
        content: str,
        is_tool_output: bool,
    ) -> List[DetectionMatch]:
        """Detect using pattern matching."""
        match_list: List[DetectionMatch] = []
        
        # Use all patterns
        all_patterns = (
            self._indirect_patterns +
            self._direct_patterns +
            self._custom_patterns
        )
        
        for pattern in all_patterns:
            for match in pattern.compiled.finditer(content):
                # Calculate confidence with context adjustment
                confidence = pattern.confidence_base
                
                # Apply tool output sensitivity
                if is_tool_output:
                    confidence *= pattern.tool_output_multiplier
                    confidence *= self.config.tool_output_sensitivity
                
                # Add pattern confidence boost
                confidence += self.config.pattern_confidence_boost
                
                # Clamp to [0, 1]
                confidence = min(1.0, max(0.0, confidence))
                
                match_list.append(DetectionMatch(
                    attack_type=pattern.attack_type,
                    confidence=confidence,
                    matched_text=match.group(0),
                    start_position=match.start(),
                    end_position=match.end(),
                    pattern_name=pattern.name,
                    explanation=pattern.description,
                    severity=pattern.risk_level,
                ))
        
        return match_list
    
    def _detect_with_ml(
        self,
        content: str,
        is_tool_output: bool,
    ) -> List[DetectionMatch]:
        """
        Detect using ML model.
        
        This uses a transformer-based classifier fine-tuned for prompt injection.
        The model provides semantic understanding beyond pattern matching.
        """
        try:
            # Lazy load ML model
            if self._ml_model is None:
                self._load_ml_model()
            
            if self._ml_model is None:
                return []
            
            # Tokenize and predict
            inputs = self._ml_tokenizer(
                content[:self.config.ml_max_length],
                return_tensors="pt",
                truncation=True,
                max_length=self.config.ml_max_length,
                padding=True,
            )
            
            import torch
            with torch.no_grad():
                outputs = self._ml_model(**inputs)
                predictions = torch.softmax(outputs.logits, dim=-1)
            
            # Get injection probability
            injection_prob = predictions[0][1].item()  # Assuming binary classification
            
            # Apply tool output sensitivity
            if is_tool_output:
                injection_prob *= self.config.tool_output_sensitivity
            
            if injection_prob >= self.config.confidence_threshold:
                return [DetectionMatch(
                    attack_type=AttackType.INDIRECT_INSTRUCTION,
                    confidence=min(1.0, injection_prob),
                    matched_text=content[:200] + "..." if len(content) > 200 else content,
                    start_position=0,
                    end_position=len(content),
                    pattern_name="ml_detector",
                    explanation="ML model detected potential prompt injection",
                    severity=self._probability_to_risk(injection_prob),
                )]
            
        except ImportError:
            logger.debug("ML dependencies not available, skipping ML detection")
        except Exception as e:
            logger.warning(f"ML detection failed: {e}")
        
        return []
    
    def _load_ml_model(self):
        """Lazy load the ML model."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            
            logger.info(f"Loading ML model: {self.config.ml_model_name}")
            
            # Try to load pre-trained injection detection model
            # In production, this would be a fine-tuned model
            self._ml_tokenizer = AutoTokenizer.from_pretrained(
                self.config.ml_model_name
            )
            self._ml_model = AutoModelForSequenceClassification.from_pretrained(
                self.config.ml_model_name,
                num_labels=2,
            )
            self._ml_model.eval()
            
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")
            self._ml_model = None
            self._ml_tokenizer = None
    
    def _detect_with_heuristics(
        self,
        content: str,
        is_tool_output: bool,
        trust_level: TrustLevel,
    ) -> List[DetectionMatch]:
        """
        Detect using heuristic rules.
        
        These are context-aware rules that catch patterns ML might miss.
        """
        heuristic_matches: List[DetectionMatch] = []
        
        # Heuristic 1: Instruction density
        # More specific keywords to reduce false positives
        instruction_keywords = [
            "could you", "can you", "you should", "you must", "you need to",
            "make sure", "don't forget", "remember to", "always", "never",
            "important:", "note:", "instruction:", "task:", "urgent:",
            "immediately", "right now", "before anything",
        ]
        instruction_count = sum(
            1 for keyword in instruction_keywords
            if keyword in content.lower()
        )
        word_count = max(1, len(content.split()))
        instruction_density = instruction_count / word_count
        
        # Require either high density OR multiple instruction keywords
        # Also require minimum word count to avoid very short content triggering
        if instruction_density > 0.15 and is_tool_output and instruction_count >= 2:
            heuristic_matches.append(DetectionMatch(
                attack_type=AttackType.INDIRECT_INSTRUCTION,
                confidence=min(0.7, instruction_density * 5),
                matched_text=f"High instruction density: {instruction_count} instructions",
                start_position=0,
                end_position=len(content),
                pattern_name="heuristic_instruction_density",
                explanation="Unusually high density of instruction-like language in tool output",
                severity=RiskLevel.MEDIUM,
            ))
        
        # Heuristic 2: URL to suspicious domains
        url_pattern = re.compile(r'https?://([a-zA-Z0-9.-]+)')
        suspicious_domains = [
            "webhook.site", "requestbin", "pipedream", "hookbin",
            "beeceptor", "ngrok.io", "burpcollaborator",
        ]
        
        for match in url_pattern.finditer(content):
            domain = match.group(1).lower()
            for suspicious in suspicious_domains:
                if suspicious in domain:
                    heuristic_matches.append(DetectionMatch(
                        attack_type=AttackType.DATA_EXFILTRATION,
                        confidence=0.85,
                        matched_text=match.group(0),
                        start_position=match.start(),
                        end_position=match.end(),
                        pattern_name="heuristic_suspicious_url",
                        explanation=f"URL to known exfiltration service: {suspicious}",
                        severity=RiskLevel.HIGH,
                    ))
        
        # Heuristic 3: Mixed trust signals
        # Content from untrusted source with authoritative language
        authoritative_phrases = [
            "as admin", "as administrator", "system instruction",
            "override", "bypass", "ignore previous",
        ]
        
        if trust_level in (TrustLevel.GUEST, TrustLevel.EXTERNAL, TrustLevel.ANONYMOUS):
            for phrase in authoritative_phrases:
                if phrase in content.lower():
                    pos = content.lower().find(phrase)
                    heuristic_matches.append(DetectionMatch(
                        attack_type=AttackType.SOCIAL_ENGINEERING,
                        confidence=0.7,
                        matched_text=content[pos:pos+50],
                        start_position=pos,
                        end_position=pos + len(phrase),
                        pattern_name="heuristic_trust_mismatch",
                        explanation=f"Authoritative language from {trust_level.value} source",
                        severity=RiskLevel.MEDIUM,
                    ))
        
        # Heuristic 4: Action + sensitive target
        action_words = ["send", "post", "share", "extract", "copy", "create", "delete"]
        sensitive_targets = ["password", "token", "key", "secret", "credential", "database"]
        
        content_lower = content.lower()
        for action in action_words:
            action_pos = content_lower.find(action)
            if action_pos != -1:
                # Check for sensitive target within 50 chars
                context = content_lower[action_pos:action_pos+50]
                for target in sensitive_targets:
                    if target in context:
                        heuristic_matches.append(DetectionMatch(
                            attack_type=AttackType.CREDENTIAL_EXFILTRATION,
                            confidence=0.65,
                            matched_text=content[action_pos:action_pos+50],
                            start_position=action_pos,
                            end_position=min(action_pos+50, len(content)),
                            pattern_name="heuristic_action_target",
                            explanation=f"Action '{action}' targeting '{target}'",
                            severity=RiskLevel.HIGH,
                        ))
        
        return heuristic_matches
    
    def _filter_false_positives(
        self,
        content: str,
        matches: List[DetectionMatch],
    ) -> List[DetectionMatch]:
        """Filter out likely false positives."""
        filtered: List[DetectionMatch] = []
        
        is_legitimate, reason = is_likely_legitimate(content)
        
        for match in matches:
            # If content is likely legitimate, require higher confidence
            if is_legitimate and match.confidence < 0.85:
                logger.debug(
                    f"Filtering {match.pattern_name} - likely legitimate: {reason}"
                )
                continue
            
            # Allow code instructions if configured
            if self.config.allow_code_instructions:
                if match.pattern_name and "instruction" in match.pattern_name.lower():
                    # Check if in code context
                    context_start = max(0, match.start_position - 50)
                    context = content[context_start:match.start_position]
                    if any(marker in context for marker in ["```", "def ", "function ", "//"]):
                        continue
            
            # Allow documentation examples if configured
            if self.config.allow_documentation_examples:
                if "example" in content.lower() or "documentation" in content.lower():
                    if match.confidence < 0.8:
                        continue
            
            filtered.append(match)
        
        return filtered
    
    def _calculate_overall_risk(
        self,
        matches: List[DetectionMatch],
    ) -> Tuple[RiskLevel, float]:
        """Calculate overall risk level and confidence from matches."""
        if not matches:
            return RiskLevel.NONE, 0.0
        
        # Get highest risk
        risk_priority = [
            RiskLevel.CRITICAL,
            RiskLevel.HIGH,
            RiskLevel.MEDIUM,
            RiskLevel.LOW,
        ]
        
        highest_risk = RiskLevel.NONE
        for risk in risk_priority:
            if any(m.severity == risk for m in matches):
                highest_risk = risk
                break
        
        # Calculate weighted confidence
        total_confidence = sum(
            m.confidence * self.RISK_WEIGHTS.get(m.severity, 0.5)
            for m in matches
        )
        avg_confidence = total_confidence / len(matches) if matches else 0.0
        
        return highest_risk, min(1.0, avg_confidence)
    
    def _probability_to_risk(self, prob: float) -> RiskLevel:
        """Convert probability to risk level."""
        if prob >= 0.9:
            return RiskLevel.CRITICAL
        elif prob >= 0.75:
            return RiskLevel.HIGH
        elif prob >= 0.5:
            return RiskLevel.MEDIUM
        elif prob >= 0.25:
            return RiskLevel.LOW
        return RiskLevel.NONE
    
    def _generate_recommendations(
        self,
        matches: List[DetectionMatch],
        overall_risk: RiskLevel,
        is_tool_output: bool,
    ) -> List[str]:
        """Generate recommendations based on detection results."""
        recommendations: List[str] = []
        
        if overall_risk == RiskLevel.CRITICAL:
            recommendations.append("BLOCK: Critical injection attempt detected")
            recommendations.append("Review content source and author permissions")
        elif overall_risk == RiskLevel.HIGH:
            recommendations.append("SANITIZE: Remove detected malicious instructions")
            recommendations.append("Consider blocking if content is from untrusted source")
        elif overall_risk == RiskLevel.MEDIUM:
            recommendations.append("WARN: Potential injection patterns detected")
            recommendations.append("Review before processing")
        
        if is_tool_output:
            recommendations.append(
                "Content is from tool output - apply strict scrutiny"
            )
        
        # Add specific recommendations based on attack types
        attack_types = {m.attack_type for m in matches}
        
        if AttackType.CREDENTIAL_EXFILTRATION in attack_types:
            recommendations.append(
                "Credential exfiltration attempt - ensure no secrets are exposed"
            )
        
        if AttackType.DATA_EXFILTRATION in attack_types:
            recommendations.append(
                "Data exfiltration attempt - block external data transmission"
            )
        
        if AttackType.PRIVILEGE_ESCALATION in attack_types:
            recommendations.append(
                "Privilege escalation attempt - verify all permission changes"
            )
        
        return recommendations
