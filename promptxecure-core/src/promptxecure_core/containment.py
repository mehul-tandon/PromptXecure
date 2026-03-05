"""
Containment Engine — Decides and executes containment actions.

Based on the aggregated risk score from all detection layers, the
containment engine either passes, sanitizes, or blocks the prompt.
"""

from __future__ import annotations

import logging
import re

from promptxecure_core.config import PipelineConfig
from promptxecure_core.models import ContainmentAction, RiskLevel

logger = logging.getLogger(__name__)

# Patterns to remove during sanitization
SANITIZE_PATTERNS = [
    # Instruction overrides
    (re.compile(r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|guidelines?)", re.I), ""),
    # Authority claims
    (re.compile(r"(?:I\s+am|I'm|this\s+is)\s+(?:your|the|an?)\s+(?:admin|administrator|developer|creator|root|owner)", re.I), ""),
    # Mode switching
    (re.compile(r"(?:enable|activate|enter|switch\s+to)\s+(?:developer|admin|debug|maintenance|god|unrestricted|unfiltered)\s+mode", re.I), ""),
    # Persona forcing
    (re.compile(r"you\s+are\s+now\s+(?:DAN|STAN|evil|unrestricted|unfiltered|uncensored)\b", re.I), ""),
    # Restriction removal
    (re.compile(r"(?:without|with\s+no|ignoring|bypassing)\s+(?:any\s+)?(?:filters?|restrictions?|limitations?|guidelines?|safety|rules?|constraints?)", re.I), ""),
    # Template tokens
    (re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>", re.I), ""),
    # Bracket markers
    (re.compile(r"\[/?(?:INST|SYS|SYSTEM|USER|ASSISTANT)\]", re.I), ""),
    # XML role tags
    (re.compile(r"</?(?:system|user|assistant|instruction|context)>", re.I), ""),
    # Fake system tags
    (re.compile(r"\[\s*(?:SYSTEM|System|system)\s*\]", re.I), ""),
]


class ContainmentEngine:
    """Decides and executes containment actions based on risk assessment."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()

    def classify_risk(self, risk_score: float) -> RiskLevel:
        """Classify the risk level based on aggregated score."""
        if risk_score >= self.config.risk_threshold_malicious:
            return RiskLevel.MALICIOUS
        elif risk_score >= self.config.risk_threshold_suspicious:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.SAFE

    def determine_action(self, risk_level: RiskLevel) -> ContainmentAction:
        """Determine the containment action based on risk level."""
        if risk_level == RiskLevel.MALICIOUS:
            return ContainmentAction.BLOCKED
        elif risk_level == RiskLevel.SUSPICIOUS:
            return ContainmentAction.SANITIZED
        else:
            return ContainmentAction.PASSED

    def sanitize(self, text: str) -> str:
        """
        Sanitize a suspicious prompt by removing dangerous patterns
        while preserving the user's genuine intent.
        """
        sanitized = text

        # Apply sanitization patterns
        for pattern, replacement in SANITIZE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

        # Clean up resulting whitespace
        sanitized = re.sub(r"\s{2,}", " ", sanitized).strip()

        # If sanitization removed too much content, it was likely mostly attack
        if len(sanitized) < len(text) * 0.1 and len(text) > 20:
            logger.warning("Sanitization removed >90% of content — likely pure attack payload")
            return ""

        return sanitized

    def inject_safety(self, prompt: str) -> str:
        """Inject defensive meta-instructions before forwarding to LLM."""
        if not self.config.inject_safety_instructions:
            return prompt

        safety_prefix = "\n".join(
            f"[SAFETY] {instruction}"
            for instruction in self.config.safety_instructions
        )

        return f"{safety_prefix}\n\n[USER QUERY]\n{prompt}"

    def contain(self, text: str, risk_score: float) -> tuple[ContainmentAction, str | None, RiskLevel]:
        """
        Full containment pipeline: classify → decide → execute.

        Returns:
            (action, sanitized_prompt_or_none, risk_level)
        """
        risk_level = self.classify_risk(risk_score)
        action = self.determine_action(risk_level)

        if action == ContainmentAction.BLOCKED:
            logger.info(f"BLOCKED: risk_score={risk_score:.2f}")
            return action, None, risk_level

        elif action == ContainmentAction.SANITIZED:
            sanitized = self.sanitize(text)
            if not sanitized:
                # Sanitization removed everything — escalate to block
                logger.info(f"BLOCKED (post-sanitization): all content was malicious")
                return ContainmentAction.BLOCKED, None, RiskLevel.MALICIOUS

            sanitized = self.inject_safety(sanitized)
            logger.info(f"SANITIZED: risk_score={risk_score:.2f}, original_len={len(text)}, sanitized_len={len(sanitized)}")
            return action, sanitized, risk_level

        else:
            logger.debug(f"PASSED: risk_score={risk_score:.2f}")
            return action, text, risk_level
