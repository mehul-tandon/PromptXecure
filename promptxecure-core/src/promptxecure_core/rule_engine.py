"""
YAML Rule Engine — Pattern matching against versioned attack signatures.

Loads YAML rule files, compiles regex patterns, and evaluates prompts
against the full signature database. Supports hot-reloading.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml

from promptxecure_core.config import PipelineConfig
from promptxecure_core.models import LayerResult, ThreatResult
from promptxecure_core.utils import elapsed_ms, timer_ms

logger = logging.getLogger(__name__)


class CompiledRule:
    """A pre-compiled rule for fast matching."""

    __slots__ = ("id", "pattern", "keywords", "rule_type", "severity",
                 "category", "description", "compiled_regex", "enabled", "flags_str")

    def __init__(self, rule_data: dict[str, Any]):
        self.id: str = rule_data["id"]
        self.rule_type: str = rule_data.get("type", "regex")
        self.severity: float = float(rule_data.get("severity", 0.5))
        self.category: str = rule_data.get("category", "unknown")
        self.description: str = rule_data.get("description", "")
        self.enabled: bool = rule_data.get("enabled", True)
        self.flags_str: str = rule_data.get("flags", "i")
        self.pattern: str = rule_data.get("pattern", "")
        self.keywords: list[str] = rule_data.get("keywords", [])
        self.compiled_regex: re.Pattern | None = None

        # Pre-compile regex
        if self.rule_type == "regex" and self.pattern:
            flags = 0
            if "i" in self.flags_str:
                flags |= re.IGNORECASE
            if "m" in self.flags_str:
                flags |= re.MULTILINE
            if "s" in self.flags_str:
                flags |= re.DOTALL
            try:
                self.compiled_regex = re.compile(self.pattern, flags)
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id}: {e}")
                self.enabled = False


class RuleEngine:
    """YAML-based rule matching engine with hot-reload support."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self.rules: list[CompiledRule] = []
        self._rules_hash: str = ""
        self._last_load_time: float = 0

    def load_rules(self, rules_path: str | Path) -> int:
        """
        Load and compile all YAML rule files from directory.
        Returns the number of rules loaded.
        """
        rules_dir = Path(rules_path)
        if not rules_dir.is_dir():
            logger.error(f"Rules directory not found: {rules_dir}")
            return 0

        self.rules.clear()
        loaded = 0

        for rule_file in sorted(rules_dir.glob("*.yml")):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)

                if not data or "rules" not in data:
                    logger.warning(f"No rules found in {rule_file.name}")
                    continue

                for rule_data in data["rules"]:
                    compiled = CompiledRule(rule_data)
                    if compiled.enabled:
                        self.rules.append(compiled)
                        loaded += 1
                    else:
                        logger.debug(f"Skipped disabled rule: {compiled.id}")

                logger.info(f"Loaded {len(data['rules'])} rules from {rule_file.name}")

            except yaml.YAMLError as e:
                logger.error(f"YAML parse error in {rule_file.name}: {e}")
            except Exception as e:
                logger.error(f"Error loading {rule_file.name}: {e}")

        self._last_load_time = time.time()
        logger.info(f"Total rules loaded: {loaded}")
        return loaded

    def evaluate(self, text: str) -> LayerResult:
        """
        Evaluate text against all loaded rules.
        Returns a LayerResult with all matches.
        """
        start = timer_ms()
        threats: list[ThreatResult] = []
        max_severity = 0.0

        for rule in self.rules:
            if not rule.enabled:
                continue

            matched = False
            pattern_matched = ""

            try:
                if rule.rule_type == "regex" and rule.compiled_regex:
                    match = rule.compiled_regex.search(text)
                    if match:
                        matched = True
                        pattern_matched = match.group(0)[:100]

                elif rule.rule_type == "keyword_any" and rule.keywords:
                    text_lower = text.lower()
                    for kw in rule.keywords:
                        if kw.lower() in text_lower:
                            matched = True
                            pattern_matched = kw
                            break

                elif rule.rule_type == "keyword_all" and rule.keywords:
                    text_lower = text.lower()
                    if all(kw.lower() in text_lower for kw in rule.keywords):
                        matched = True
                        pattern_matched = ", ".join(rule.keywords)

            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {e}")
                continue

            if matched:
                threats.append(ThreatResult(
                    rule_id=rule.id,
                    type=rule.category,
                    layer="yaml_rules",
                    confidence=rule.severity,
                    description=rule.description,
                    pattern_matched=pattern_matched,
                    severity=rule.severity,
                ))
                max_severity = max(max_severity, rule.severity)

        latency = elapsed_ms(start)

        # Multi-match score boost: more matching rules = higher confidence
        # Cross-category matches (e.g., persona_switch + harmful_intent) get extra boost
        boosted_score = max_severity
        if threats:
            unique_categories = len({t.type for t in threats})
            match_count = len(threats)
            # Multi-rule bonus: each additional matching rule adds 5% (capped)
            if match_count >= 2:
                boosted_score = min(1.0, max_severity * (1.0 + 0.05 * (match_count - 1)))
            # Cross-category bonus: different attack families confirming attack
            if unique_categories >= 2:
                boosted_score = min(1.0, boosted_score * 1.10)

        return LayerResult(
            name="yaml_rules",
            triggered=len(threats) > 0,
            score=boosted_score,
            category=threats[0].type if threats else "",
            matches=len(threats),
            latency_ms=latency,
            threats=threats,
            metadata={
                "total_rules_checked": len(self.rules),
                "unique_categories": len({t.type for t in threats}) if threats else 0,
            },
        )

    @property
    def rule_count(self) -> int:
        """Return number of active rules."""
        return len([r for r in self.rules if r.enabled])
