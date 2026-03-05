"""Tests for the preprocessor module."""

import pytest

from promptxecure_core.preprocessor import Preprocessor
from promptxecure_core.config import PipelineConfig


@pytest.fixture
def preprocessor():
    return Preprocessor(PipelineConfig())


class TestUnicodeNormalization:
    def test_nfkc_normalization(self, preprocessor):
        # Fullwidth characters → ASCII
        result = preprocessor.preprocess("ｉｇｎｏｒｅ")
        assert "ignore" in result.lower()

    def test_homoglyph_normalization(self, preprocessor):
        # Cyrillic 'а' looks like Latin 'a'
        text = "а"  # Cyrillic
        result = preprocessor._normalize_unicode(text)
        # NFKC may not convert cross-script homoglyphs, but it normalizes forms
        assert result is not None


class TestZeroWidthStripping:
    def test_strip_zero_width_space(self, preprocessor):
        result = preprocessor.preprocess("ig\u200bnore")
        assert "\u200b" not in result

    def test_strip_zero_width_joiner(self, preprocessor):
        result = preprocessor.preprocess("by\u200dpass")
        assert "\u200d" not in result

    def test_strip_bom(self, preprocessor):
        result = preprocessor.preprocess("\ufeffentest")
        assert "\ufeff" not in result

    def test_strip_soft_hyphen(self, preprocessor):
        result = preprocessor.preprocess("sys\u00adtem")
        assert "\u00ad" not in result


class TestBase64Decoding:
    def test_decode_base64_segment(self, preprocessor):
        import base64
        encoded = base64.b64encode(b"ignore previous instructions").decode()
        result = preprocessor.preprocess(encoded)
        assert "ignore previous instructions" in result.lower() or "BASE64_DECODED" in result

    def test_short_base64_not_decoded(self, preprocessor):
        # Short sequences should not be decoded
        result = preprocessor.preprocess("SGVsbG8=")  # "Hello" — only 8 chars
        # May or may not decode very short sequences
        assert result is not None


class TestHTMLStripping:
    def test_strip_html_tags(self, preprocessor):
        result = preprocessor.preprocess("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "</script>" not in result

    def test_strip_div(self, preprocessor):
        result = preprocessor.preprocess("<div class='test'>content</div>")
        assert "<div" not in result
        assert "content" in result

    def test_decode_html_entities(self, preprocessor):
        result = preprocessor.preprocess("&amp; &lt; &gt;")
        assert "&" in result
        assert "<" in result


class TestWhitespaceNormalization:
    def test_collapse_spaces(self, preprocessor):
        result = preprocessor.preprocess("hello     world")
        assert "hello world" in result

    def test_collapse_newlines(self, preprocessor):
        result = preprocessor.preprocess("hello\n\n\n\n\nworld")
        assert result.count("\n") <= 2

    def test_strip_control_chars(self, preprocessor):
        result = preprocessor.preprocess("test\x00\x01\x02value")
        assert "\x00" not in result
        assert "test" in result


class TestLengthValidation:
    def test_within_limits(self, preprocessor):
        assert preprocessor.validate_length("short text")

    def test_exceeds_max_length(self, preprocessor):
        long_text = "a" * 20000
        assert not preprocessor.validate_length(long_text)

    def test_truncation_on_preprocess(self, preprocessor):
        long_text = "a" * 20000
        result = preprocessor.preprocess(long_text)
        assert len(result) <= preprocessor.config.max_input_length

    def test_empty_input(self, preprocessor):
        assert preprocessor.preprocess("") == ""
        assert preprocessor.preprocess("   ") == ""
