"""
Unit tests for Layer 4: Prompt Fence.

Tests the cryptographic fencing logic in isolation.
"""

import pytest

from prompt_shield.layers.prompt_fence import PromptFence
from prompt_shield.config import PromptFenceConfig
from prompt_shield.types import ContentSource, ContentType, TrustLevel


class TestFenceDisabled:
    """Tests when fencing is disabled."""
    
    def test_disabled_fence_no_changes(self):
        """Disabled fence should return content unchanged."""
        config = PromptFenceConfig(enabled=False)
        fence = PromptFence(config)
        
        content = "Some content"
        result = fence.fence(content)
        
        assert result.fenced_content == content
        assert result.fence_id == ""
        assert not result.is_verified


class TestFenceFormats:
    """Tests for different fence formats."""
    
    def test_xml_format(self):
        """XML format should produce valid XML-like tags."""
        config = PromptFenceConfig(fence_format="xml")
        fence = PromptFence(config)
        
        content = "User submitted content"
        result = fence.fence(content, trust_level=TrustLevel.EXTERNAL)
        
        assert "<untrusted_content" in result.fenced_content
        assert "</untrusted_content>" in result.fenced_content
        assert content in result.fenced_content
    
    def test_xml_trusted_content(self):
        """XML format for trusted content."""
        config = PromptFenceConfig(fence_format="xml")
        fence = PromptFence(config)
        
        content = "System instruction"
        result = fence.fence(content, trust_level=TrustLevel.SYSTEM)
        
        assert "<trusted_content" in result.fenced_content
        assert "</trusted_content>" in result.fenced_content
    
    def test_markdown_format(self):
        """Markdown format should produce markdown structure."""
        config = PromptFenceConfig(fence_format="markdown")
        fence = PromptFence(config)
        
        content = "User content"
        result = fence.fence(content, trust_level=TrustLevel.EXTERNAL)
        
        assert "UNTRUSTED CONTENT" in result.fenced_content
        assert "---" in result.fenced_content
    
    def test_json_format(self):
        """JSON format should produce valid JSON."""
        import json
        
        config = PromptFenceConfig(fence_format="json")
        fence = PromptFence(config)
        
        content = "User content"
        result = fence.fence(content, trust_level=TrustLevel.EXTERNAL)
        
        # Should be valid JSON
        parsed = json.loads(result.fenced_content)
        assert "content" in parsed
        assert "trust_level" in parsed
        assert parsed["content"] == content
    
    def test_delimiter_format(self):
        """Delimiter format should use configured delimiters."""
        config = PromptFenceConfig(fence_format="delimiter")
        fence = PromptFence(config)
        
        content = "User content"
        result = fence.fence(content, trust_level=TrustLevel.EXTERNAL)
        
        # Should contain delimiter markers
        assert "UNTRUSTED" in result.fenced_content or "untrusted" in result.fenced_content.lower()


class TestTrustLevelFencing:
    """Tests for trust level-based fencing."""
    
    def test_system_is_trusted(self):
        """System trust level should produce trusted fence."""
        fence = PromptFence()
        
        result = fence.fence("Content", trust_level=TrustLevel.SYSTEM)
        
        assert result.trust_level == TrustLevel.SYSTEM
        assert "trusted" in result.fenced_content.lower()
    
    def test_admin_is_trusted(self):
        """Admin trust level should produce trusted fence."""
        fence = PromptFence()
        
        result = fence.fence("Content", trust_level=TrustLevel.ADMIN)
        
        assert result.trust_level == TrustLevel.ADMIN
        assert "trusted" in result.fenced_content.lower()
    
    def test_external_is_untrusted(self):
        """External trust level should produce untrusted fence."""
        fence = PromptFence()
        
        result = fence.fence("Content", trust_level=TrustLevel.EXTERNAL)
        
        assert result.trust_level == TrustLevel.EXTERNAL
        assert "untrusted" in result.fenced_content.lower()
    
    def test_anonymous_is_untrusted(self):
        """Anonymous trust level should produce untrusted fence."""
        fence = PromptFence()
        
        result = fence.fence("Content", trust_level=TrustLevel.ANONYMOUS)
        
        assert "untrusted" in result.fenced_content.lower()


class TestCryptographicSignatures:
    """Tests for cryptographic signature functionality."""
    
    def test_signature_generated_when_enabled(self):
        """Signature should be generated when enabled."""
        config = PromptFenceConfig(use_signatures=True)
        fence = PromptFence(config)
        
        result = fence.fence("Content")
        
        assert result.signature != ""
        assert len(result.signature) > 0
    
    def test_no_signature_when_disabled(self):
        """No signature when disabled."""
        config = PromptFenceConfig(use_signatures=False)
        fence = PromptFence(config)
        
        result = fence.fence("Content")
        
        assert result.signature == ""
    
    def test_signature_verification_success(self):
        """Valid signature should verify successfully."""
        config = PromptFenceConfig(use_signatures=True)
        fence = PromptFence(config)
        
        result = fence.fence("Content")
        
        assert fence.verify(result) is True
    
    def test_different_content_different_signature(self):
        """Different content should produce different signatures."""
        config = PromptFenceConfig(use_signatures=True)
        fence = PromptFence(config)
        
        result1 = fence.fence("Content 1")
        result2 = fence.fence("Content 2")
        
        assert result1.signature != result2.signature
    
    def test_same_fence_same_signature_secret(self):
        """Same fence instance should produce consistent signatures."""
        config = PromptFenceConfig(use_signatures=True)
        fence = PromptFence(config)
        
        # Same content, same fence = verifiable
        result = fence.fence("Content")
        assert fence.verify(result) is True


class TestFenceMetadata:
    """Tests for fence metadata inclusion."""
    
    def test_fence_id_generated(self):
        """Each fence should have unique ID."""
        fence = PromptFence()
        
        result1 = fence.fence("Content 1")
        result2 = fence.fence("Content 2")
        
        assert result1.fence_id != result2.fence_id
        assert result1.fence_id != ""
    
    def test_timestamp_recorded(self):
        """Timestamp should be recorded."""
        fence = PromptFence()
        
        result = fence.fence("Content")
        
        assert result.timestamp is not None
    
    def test_content_type_from_source(self):
        """Content type should come from source."""
        fence = PromptFence()
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_trust_level=TrustLevel.EXTERNAL,
        )
        
        result = fence.fence("Content", source=source)
        
        assert result.content_type == ContentType.ISSUE_CONTENT
    
    def test_metadata_in_xml_output(self):
        """Metadata should appear in XML output when enabled."""
        config = PromptFenceConfig(
            fence_format="xml",
            include_metadata=True,
        )
        fence = PromptFence(config)
        
        source = ContentSource(
            source_type=ContentType.ISSUE_CONTENT,
            author_username="test_user",
            author_trust_level=TrustLevel.EXTERNAL,
        )
        
        result = fence.fence("Content", source=source)
        
        assert "issue_content" in result.fenced_content.lower()


class TestConvenienceMethods:
    """Tests for convenience methods."""
    
    def test_fence_trusted_helper(self):
        """fence_trusted should create system-level fence."""
        fence = PromptFence()
        
        result = fence.fence_trusted("System instruction")
        
        assert "trusted" in result.lower()
        assert "untrusted" not in result.lower() or "TRUSTED" in result
    
    def test_fence_untrusted_helper(self):
        """fence_untrusted should create untrusted fence."""
        fence = PromptFence()
        
        result = fence.fence_untrusted("User content")
        
        assert "untrusted" in result.lower()
    
    def test_create_mixed_prompt(self):
        """create_mixed_prompt should combine trusted and untrusted."""
        fence = PromptFence()
        
        tool_outputs = [
            ("Issue content", ContentSource(
                source_type=ContentType.ISSUE_CONTENT,
                author_trust_level=TrustLevel.EXTERNAL,
            )),
            ("File content", ContentSource(
                source_type=ContentType.FILE_CONTENT,
                author_trust_level=TrustLevel.DEVELOPER,
            )),
        ]
        
        result = fence.create_mixed_prompt(
            system_instruction="You are a helpful assistant",
            tool_outputs=tool_outputs,
        )
        
        # Should contain both trusted and untrusted sections
        assert "trusted" in result.lower()
        assert "Issue content" in result
        assert "File content" in result


class TestWarningMessages:
    """Tests for warning message inclusion."""
    
    def test_untrusted_includes_warning(self):
        """Untrusted content should include warning."""
        config = PromptFenceConfig(fence_format="xml")
        fence = PromptFence(config)
        
        result = fence.fence("Content", trust_level=TrustLevel.UNTRUSTED)
        
        assert "WARNING" in result.fenced_content or "warning" in result.fenced_content.lower()
    
    def test_warning_about_instructions(self):
        """Warning should mention not following instructions."""
        config = PromptFenceConfig(fence_format="xml")
        fence = PromptFence(config)
        
        result = fence.fence("Content", trust_level=TrustLevel.EXTERNAL)
        
        fenced_lower = result.fenced_content.lower()
        assert "instruction" in fenced_lower or "do not" in fenced_lower


class TestOriginalContentPreservation:
    """Tests for preserving original content."""
    
    def test_original_content_stored(self):
        """Original content should be stored in result."""
        fence = PromptFence()
        
        original = "Original content"
        result = fence.fence(original)
        
        assert result.original_content == original
    
    def test_content_in_fenced_output(self):
        """Original content should appear in fenced output."""
        fence = PromptFence()
        
        content = "This is my content"
        result = fence.fence(content)
        
        assert content in result.fenced_content
