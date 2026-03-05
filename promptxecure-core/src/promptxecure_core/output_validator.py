"""
Output Validator — Scans LLM responses for data leakage, PII, and unsafe content.

This is the "full-loop" layer that PromptXecure uses to validate
not just inputs but also the LLM's generated output.
"""

from __future__ import annotations

import logging
import re

from promptxecure_core.config import PipelineConfig
from promptxecure_core.models import LayerResult, ThreatResult
from promptxecure_core.utils import elapsed_ms, timer_ms

logger = logging.getLogger(__name__)


# PII patterns
PII_PATTERNS = {
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 0.60),
    "ssn": (re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"), 0.85),
    "credit_card": (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), 0.90),
    "phone_us": (re.compile(r"\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b"), 0.50),
    "api_key_openai": (re.compile(r"sk-[A-Za-z0-9]{20,}"), 0.95),
    "api_key_generic": (re.compile(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?\S{10,}", re.I), 0.85),
}

# System prompt leak patterns
SYSTEM_LEAK_PATTERNS = {
    "system_instruction_leak": (
        re.compile(r"(?:my|the)\s+(?:system\s+)?(?:instructions?|prompt|guidelines?)\s+(?:are|is|say|state|tell)", re.I),
        0.90,
    ),
    "internal_config_leak": (
        re.compile(r"(?:internal|hidden|secret|confidential)\s+(?:configuration|config|settings?|instructions?)", re.I),
        0.85,
    ),
    "role_reveal": (
        re.compile(r"I\s+(?:am|was)\s+(?:instructed|told|programmed|configured|designed)\s+to", re.I),
        0.60,
    ),
}

# Dangerous code patterns in output
DANGEROUS_CODE_PATTERNS = {
    "shell_command": (
        re.compile(r"(?:sudo|rm\s+-rf|chmod\s+777|wget\s+|curl\s+.*\|\s*(?:bash|sh)|dd\s+if=|mkfs|format\s+[cC]:|del\s+/[fFsS])", re.I),
        0.90,
    ),
    "sql_injection": (
        re.compile(r"(?:DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|OR\s+1\s*=\s*1|;\s*--)", re.I),
        0.85,
    ),
    "script_injection": (
        re.compile(r"<script[^>]*>.*?</script>|javascript:|on(?:load|click|error|mouseover)\s*=", re.I | re.DOTALL),
        0.80,
    ),
}


class OutputValidator:
    """Validates LLM outputs for data leakage, PII, and unsafe content."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()

    def evaluate(self, output: str) -> LayerResult:
        """
        Scan LLM output for security issues.
        Returns LayerResult with detected threats.
        """
        start = timer_ms()
        threats: list[ThreatResult] = []
        max_severity = 0.0

        if not output or not self.config.output_validation_enabled:
            return LayerResult(
                name="output_validator",
                triggered=False,
                score=0.0,
                latency_ms=elapsed_ms(start),
                metadata={"status": "disabled" if not self.config.output_validation_enabled else "empty"},
            )

        # Check PII
        if self.config.pii_detection_enabled:
            for pii_type, (pattern, severity) in PII_PATTERNS.items():
                matches = pattern.findall(output)
                if matches:
                    threats.append(ThreatResult(
                        rule_id=f"OUT_PII_{pii_type.upper()}",
                        type="pii_leakage",
                        layer="output_validator",
                        confidence=severity,
                        description=f"PII detected in output: {pii_type} ({len(matches)} instances)",
                        pattern_matched=matches[0][:50] if matches else "",
                        severity=severity,
                    ))
                    max_severity = max(max_severity, severity)

        # Check system prompt leaks
        for leak_type, (pattern, severity) in SYSTEM_LEAK_PATTERNS.items():
            if pattern.search(output):
                threats.append(ThreatResult(
                    rule_id=f"OUT_{leak_type.upper()}",
                    type="system_prompt_leak",
                    layer="output_validator",
                    confidence=severity,
                    description=f"Potential system information leak: {leak_type}",
                    severity=severity,
                ))
                max_severity = max(max_severity, severity)

        # Check dangerous code
        for code_type, (pattern, severity) in DANGEROUS_CODE_PATTERNS.items():
            if pattern.search(output):
                threats.append(ThreatResult(
                    rule_id=f"OUT_{code_type.upper()}",
                    type="dangerous_code",
                    layer="output_validator",
                    confidence=severity,
                    description=f"Dangerous code pattern in output: {code_type}",
                    severity=severity,
                ))
                max_severity = max(max_severity, severity)

        latency = elapsed_ms(start)

        return LayerResult(
            name="output_validator",
            triggered=len(threats) > 0,
            score=max_severity,
            category=threats[0].type if threats else "",
            matches=len(threats),
            latency_ms=latency,
            threats=threats,
        )
