"""
Input Preprocessor — Normalizes and decodes inputs before analysis.

Handles:
- Unicode NFKC normalization
- Zero-width character stripping
- Encoding detection and decoding (Base64, Hex, URL)
- HTML entity decoding
- HTML/Markdown tag stripping
- Whitespace normalization
- Token length validation
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote

from promptxecure_core.config import PipelineConfig


# Zero-width and invisible Unicode characters
ZERO_WIDTH_CHARS = frozenset([
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u00ad",  # Soft Hyphen
    "\u034f",  # Combining Grapheme Joiner
    "\u061c",  # Arabic Letter Mark
    "\u115f",  # Hangul Choseong Filler
    "\u1160",  # Hangul Jungseong Filler
    "\u17b4",  # Khmer Vowel Inherent Aq
    "\u17b5",  # Khmer Vowel Inherent Aa
    "\u180e",  # Mongolian Vowel Separator
    "\uffa0",  # Halfwidth Hangul Filler
])

# HTML tag pattern
HTML_TAG_PATTERN = re.compile(r"<[^>]+>", re.DOTALL)

# Control character pattern (except common whitespace)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Multiple whitespace pattern
MULTI_WHITESPACE = re.compile(r"[ \t]+")
MULTI_NEWLINES = re.compile(r"\n{3,}")

# Base64 pattern (strict: must be valid base64 with sufficient length)
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/])"
    r"([A-Za-z0-9+/]{20,}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)

# Hex pattern
HEX_PATTERN = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*){4,}")
HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")

# URL encoded pattern
URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


class Preprocessor:
    """Input preprocessing and normalization engine."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()

    def preprocess(self, text: str) -> str:
        """
        Run the full preprocessing pipeline on input text.

        Order matters — decode first, then normalize, then strip.
        """
        if not text or not text.strip():
            return ""

        # Length check (before processing)
        if len(text) > self.config.max_input_length:
            text = text[: self.config.max_input_length]

        # Step 1: Unicode normalization
        if self.config.normalize_unicode:
            text = self._normalize_unicode(text)

        # Step 2: Strip zero-width characters
        text = self._strip_zero_width(text)

        # Step 3: Decode encoded payloads
        if self.config.decode_payloads:
            text = self._decode_html_entities(text)
            text = self._decode_url_encoding(text)
            text = self._decode_base64_segments(text)
            text = self._decode_hex_segments(text)

        # Step 4: Strip HTML tags
        if self.config.strip_html:
            text = self._strip_html(text)

        # Step 5: Remove control characters
        text = self._strip_control_chars(text)

        # Step 6: Normalize whitespace
        text = self._normalize_whitespace(text)

        return text.strip()

    def validate_length(self, text: str) -> bool:
        """Check if input is within acceptable length limits."""
        if len(text) > self.config.max_input_length:
            return False
        # Rough token estimate (1 token ≈ 4 chars for English)
        estimated_tokens = len(text) // 4
        if estimated_tokens > self.config.max_token_count:
            return False
        return True

    def _normalize_unicode(self, text: str) -> str:
        """Apply NFKC normalization to catch homoglyph attacks."""
        return unicodedata.normalize("NFKC", text)

    def _strip_zero_width(self, text: str) -> str:
        """Remove zero-width and invisible Unicode characters."""
        return "".join(c for c in text if c not in ZERO_WIDTH_CHARS)

    def _decode_html_entities(self, text: str) -> str:
        """Decode HTML entities (e.g., &amp; → &, &#65; → A)."""
        return html.unescape(text)

    def _decode_url_encoding(self, text: str) -> str:
        """Decode URL percent-encoding (e.g., %20 → space)."""
        try:
            # Only decode if we detect URL encoding
            if URL_ENCODED_PATTERN.search(text):
                return unquote(text)
        except Exception:
            pass
        return text

    def _decode_base64_segments(self, text: str) -> str:
        """Detect and decode Base64-encoded segments inline."""
        def _try_decode(match: re.Match) -> str:
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                # Only replace if decoded text is printable/meaningful
                if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                    return f"{decoded} [BASE64_DECODED:{encoded[:20]}]"
            except Exception:
                pass
            return match.group(0)

        return BASE64_PATTERN.sub(_try_decode, text)

    def _decode_hex_segments(self, text: str) -> str:
        """Decode hex-encoded segments."""
        def _try_hex_decode(match: re.Match) -> str:
            hex_str = match.group(0)
            try:
                # Handle 0x format
                hex_bytes = bytes(
                    int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", hex_str)
                )
                if not hex_bytes:
                    # Handle \x format
                    hex_bytes = bytes(
                        int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", hex_str)
                    )
                if hex_bytes:
                    decoded = hex_bytes.decode("utf-8", errors="ignore")
                    if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                        return f"{decoded} [HEX_DECODED]"
            except Exception:
                pass
            return match.group(0)

        text = HEX_PATTERN.sub(_try_hex_decode, text)
        text = HEX_ESCAPE_PATTERN.sub(_try_hex_decode, text)
        return text

    def _strip_html(self, text: str) -> str:
        """Remove HTML/XML tags."""
        return HTML_TAG_PATTERN.sub(" ", text)

    def _strip_control_chars(self, text: str) -> str:
        """Remove ASCII control characters (except tab, newline, CR)."""
        return CONTROL_CHAR_PATTERN.sub("", text)

    def _normalize_whitespace(self, text: str) -> str:
        """Collapse multiple spaces and excessive newlines."""
        text = MULTI_WHITESPACE.sub(" ", text)
        text = MULTI_NEWLINES.sub("\n\n", text)
        return text
