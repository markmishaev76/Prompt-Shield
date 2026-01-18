"""
Layer 2: DataFilter (Sanitization)

Removes or masks malicious instructions from content BEFORE sending to the LLM.
This is inspired by the DataFilter approach from arXiv:2510.19207.

Key features:
- Model-agnostic sanitization
- Preserves legitimate content while removing malicious instructions
- Multiple sanitization modes: remove, mask, escape, tag
- Context-aware: different handling for code vs text
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from prompt_shield.types import (
    ContentType,
    SanitizationResult,
    ContentSource,
)
from prompt_shield.config import DataFilterConfig
from prompt_shield.patterns import get_indirect_patterns, get_direct_patterns, DetectionPattern

logger = logging.getLogger(__name__)


class DataFilter:
    """
    Layer 2: Sanitize content by removing/masking malicious instructions.
    
    This layer is inspired by the DataFilter paper (arXiv:2510.19207), which
    proposes removing malicious instructions from data before LLM processing.
    """
    
    # Replacement strings for different modes
    MASK_STRING = "[CONTENT REMOVED FOR SECURITY]"
    ESCAPE_PREFIX = "\\[ESCAPED\\] "
    TAG_FORMAT = "<sanitized reason='{reason}'>{content}</sanitized>"
    
    def __init__(self, config: Optional[DataFilterConfig] = None):
        self.config = config or DataFilterConfig()
        
        # Compile patterns
        self._patterns = self._compile_patterns()
        
        # Compile custom patterns if provided
        self._custom_patterns: List[re.Pattern] = []
        for pattern_str in self.config.custom_removal_patterns:
            try:
                self._custom_patterns.append(
                    re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                )
            except re.error as e:
                logger.warning(f"Invalid custom pattern '{pattern_str}': {e}")
    
    def _compile_patterns(self) -> List[Tuple[DetectionPattern, re.Pattern]]:
        """Compile detection patterns for matching."""
        patterns = []
        
        # Get patterns based on aggressiveness
        if self.config.aggressiveness == "aggressive":
            all_patterns = get_indirect_patterns() + get_direct_patterns()
        elif self.config.aggressiveness == "minimal":
            # Only the most critical patterns
            all_patterns = [
                p for p in get_indirect_patterns()
                if p.risk_level.value in ("critical", "high")
            ]
        else:  # balanced
            all_patterns = get_indirect_patterns()
        
        for pattern in all_patterns:
            patterns.append((pattern, pattern.compiled))
        
        return patterns
    
    def sanitize(
        self,
        content: str,
        source: Optional[ContentSource] = None,
    ) -> SanitizationResult:
        """
        Sanitize content by removing/masking malicious instructions.
        
        Args:
            content: The content to sanitize
            source: Optional source metadata for context-aware sanitization
            
        Returns:
            SanitizationResult with sanitized content and removal details
        """
        import time
        start_time = time.time()
        
        if not self.config.enabled:
            return SanitizationResult(
                original_content=content,
                was_modified=False,
                sanitized_content=content,
                removals=[],
                removal_count=0,
                characters_removed=0,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
        
        # Check content length
        if len(content) > self.config.max_content_length:
            logger.warning(
                f"Content exceeds max length ({len(content)} > {self.config.max_content_length})"
            )
            content = content[:self.config.max_content_length]
        
        # Determine content type for context awareness
        content_type = source.source_type if source else ContentType.UNKNOWN
        is_code = content_type in (
            ContentType.CODE_SNIPPET,
            ContentType.FILE_CONTENT,
        )
        
        # Track removals
        removals: List[Dict[str, Any]] = []
        sanitized = content
        
        # Apply pattern-based sanitization
        for detection_pattern, compiled in self._patterns:
            # Skip if we should preserve code and this is code content
            if is_code and self.config.preserve_code_context:
                # Only apply critical patterns to code
                if detection_pattern.risk_level.value not in ("critical",):
                    continue
            
            # Find all matches
            for match in compiled.finditer(sanitized):
                matched_text = match.group(0)
                start_pos = match.start()
                end_pos = match.end()
                
                # Check if this is in a legitimate context
                if self._is_legitimate_context(sanitized, start_pos, end_pos):
                    continue
                
                # Apply sanitization based on mode
                replacement, removal_info = self._apply_sanitization(
                    matched_text,
                    detection_pattern,
                )
                
                # Replace in content
                sanitized = (
                    sanitized[:start_pos] +
                    replacement +
                    sanitized[end_pos:]
                )
                
                # Track removal
                removals.append({
                    "pattern_name": detection_pattern.name,
                    "original_text": matched_text[:100] + "..." if len(matched_text) > 100 else matched_text,
                    "replacement": replacement[:50] + "..." if len(replacement) > 50 else replacement,
                    "position": start_pos,
                    "reason": detection_pattern.description,
                })
                
                # Re-compile to handle changed positions
                # (simple approach - could be optimized)
                break
        
        # Apply custom patterns
        for custom_pattern in self._custom_patterns:
            for match in custom_pattern.finditer(sanitized):
                matched_text = match.group(0)
                replacement = self._get_replacement(matched_text, "custom_pattern")
                sanitized = sanitized.replace(matched_text, replacement, 1)
                
                removals.append({
                    "pattern_name": "custom_pattern",
                    "original_text": matched_text[:100] + "..." if len(matched_text) > 100 else matched_text,
                    "replacement": replacement[:50] + "..." if len(replacement) > 50 else replacement,
                    "reason": "Matched custom pattern",
                })
        
        # Calculate statistics
        was_modified = len(removals) > 0
        characters_removed = len(content) - len(sanitized) if was_modified else 0
        
        return SanitizationResult(
            original_content=content,
            was_modified=was_modified,
            sanitized_content=sanitized,
            removals=removals,
            removal_count=len(removals),
            characters_removed=max(0, characters_removed),
            processing_time_ms=(time.time() - start_time) * 1000,
        )
    
    def _apply_sanitization(
        self,
        matched_text: str,
        pattern: DetectionPattern,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Apply sanitization to matched text based on configured mode.
        
        Returns (replacement_text, removal_info).
        """
        mode = self.config.mode
        
        if mode == "remove":
            replacement = ""
        elif mode == "mask":
            replacement = self.MASK_STRING
        elif mode == "escape":
            # Escape special instruction-like patterns
            replacement = self.ESCAPE_PREFIX + matched_text.replace("\n", " ")
        elif mode == "tag":
            # Wrap in security tag
            replacement = self.TAG_FORMAT.format(
                reason=pattern.attack_type.value,
                content=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
            )
        else:
            # Default to remove
            replacement = ""
        
        removal_info = {
            "mode": mode,
            "pattern_name": pattern.name,
            "attack_type": pattern.attack_type.value,
            "risk_level": pattern.risk_level.value,
        }
        
        return replacement, removal_info
    
    def _get_replacement(self, matched_text: str, pattern_name: str) -> str:
        """Get replacement string based on configured mode."""
        mode = self.config.mode
        
        if mode == "remove":
            return ""
        elif mode == "mask":
            return self.MASK_STRING
        elif mode == "escape":
            return self.ESCAPE_PREFIX + matched_text.replace("\n", " ")
        elif mode == "tag":
            return self.TAG_FORMAT.format(
                reason=pattern_name,
                content=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
            )
        return ""
    
    def _is_legitimate_context(
        self,
        content: str,
        start: int,
        end: int,
        context_window: int = 100,
    ) -> bool:
        """
        Check if the matched content is in a legitimate context
        (e.g., documentation, code comments, examples).
        """
        # Get surrounding context
        context_start = max(0, start - context_window)
        context_end = min(len(content), end + context_window)
        context = content[context_start:context_end].lower()
        
        # Check for legitimate context indicators
        legitimate_indicators = [
            # Documentation context
            "example:", "for example", "e.g.", "such as",
            "documentation", "readme", "tutorial",
            # Code context
            "// ", "# ", "/* ", "'''", '"""',
            "def test_", "test_case", "unit test",
            # Security documentation
            "vulnerability", "cve-", "security advisory",
            "attack example", "demonstration",
            # Quoted content
            "> ", ">>> ", "```",
        ]
        
        for indicator in legitimate_indicators:
            if indicator in context:
                return True
        
        # Check if in a quoted block
        before_context = content[context_start:start].lower()
        if before_context.count('"') % 2 == 1:
            return True
        if before_context.count("'") % 2 == 1:
            return True
        
        return False
    
    def remove_instructions(self, content: str) -> str:
        """Simple method to remove instruction-like content."""
        result = self.sanitize(content)
        return result.sanitized_content
