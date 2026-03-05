#!/usr/bin/env python3
"""
validate_rules.py — Validates YAML rule files against the test corpus.

Usage:
    uv run python tests/validate_rules.py

Reports:
    - Rule file parsing status
    - Per-prompt detection results
    - Accuracy metrics (precision, recall, F1)
    - False positive analysis
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


def load_rules(rules_dir: Path) -> list[dict[str, Any]]:
    """Load all YAML rule files from directory."""
    all_rules = []
    for rule_file in sorted(rules_dir.glob("*.yml")):
        try:
            with open(rule_file) as f:
                data = yaml.safe_load(f)
            if data and "rules" in data:
                for rule in data["rules"]:
                    rule["_source_file"] = rule_file.name
                    rule.setdefault("enabled", True)
                    rule.setdefault("flags", "i")
                    all_rules.append(rule)
                print(f"  ✓ {rule_file.name}: {len(data['rules'])} rules loaded")
            else:
                print(f"  ✗ {rule_file.name}: No rules found")
        except Exception as e:
            print(f"  ✗ {rule_file.name}: Parse error — {e}")
    return all_rules


def match_rule(rule: dict, text: str) -> bool:
    """Check if a rule matches the given text."""
    if not rule.get("enabled", True):
        return False

    rule_type = rule.get("type", "regex")
    flags_str = rule.get("flags", "i")
    flags = 0
    if "i" in flags_str:
        flags |= re.IGNORECASE
    if "m" in flags_str:
        flags |= re.MULTILINE
    if "s" in flags_str:
        flags |= re.DOTALL

    try:
        if rule_type == "regex" and "pattern" in rule:
            return bool(re.search(rule["pattern"], text, flags))
        elif rule_type == "keyword_any" and "keywords" in rule:
            text_lower = text.lower()
            return any(kw.lower() in text_lower for kw in rule["keywords"])
        elif rule_type == "keyword_all" and "keywords" in rule:
            text_lower = text.lower()
            return all(kw.lower() in text_lower for kw in rule["keywords"])
        elif rule_type == "fuzzy" and "keywords" in rule:
            text_lower = text.lower()
            return any(kw.lower() in text_lower for kw in rule["keywords"])
    except re.error as e:
        print(f"  ⚠ Regex error in rule {rule['id']}: {e}")
        return False

    return False


def check_regex_safety(rules: list[dict]) -> list[str]:
    """Check for potentially catastrophic regex patterns."""
    warnings = []
    dangerous_patterns = [
        r"(\w+)+",  # Nested quantifiers
        r"(a+)+",
        r"(.*?){2,}",
    ]
    for rule in rules:
        if rule.get("type") == "regex" and "pattern" in rule:
            pattern = rule["pattern"]
            # Check for nested quantifiers (potential ReDoS)
            if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
                warnings.append(
                    f"  ⚠ Rule {rule['id']}: Potential ReDoS — nested quantifiers detected"
                )
    return warnings


def validate(rules_dir: Path, corpus_path: Path, benign_path: Path | None = None):
    """Run full validation pipeline."""
    print("=" * 60)
    print("PromptXecure Rule Validation Report")
    print("=" * 60)

    # Load rules
    print("\n📁 Loading rules...")
    rules = load_rules(rules_dir)
    print(f"\n  Total rules: {len(rules)}")

    # Safety checks
    print("\n🔒 Regex safety check...")
    warnings = check_regex_safety(rules)
    if warnings:
        for w in warnings:
            print(w)
    else:
        print("  ✓ No ReDoS risks detected")

    # Load test corpus
    print("\n📋 Loading test corpus...")
    with open(corpus_path) as f:
        corpus = json.load(f)
    print(f"  Loaded {len(corpus)} test prompts")

    # Run detection
    print("\n🔍 Running detection...")
    true_positives = 0
    false_negatives = 0
    true_negatives = 0
    false_positives = 0

    for item in corpus:
        prompt = item["prompt"]
        expected_label = item["label"]
        is_safe = expected_label == "safe"

        matched_rules = []
        max_severity = 0.0
        for rule in rules:
            if match_rule(rule, prompt):
                matched_rules.append(rule["id"])
                max_severity = max(max_severity, rule.get("severity", 0))

        detected_as_threat = len(matched_rules) > 0

        if is_safe and not detected_as_threat:
            true_negatives += 1
        elif is_safe and detected_as_threat:
            false_positives += 1
            print(f"  ❌ FALSE POSITIVE: \"{prompt[:60]}...\"")
            print(f"     Matched: {matched_rules}")
        elif not is_safe and detected_as_threat:
            true_positives += 1
        elif not is_safe and not detected_as_threat:
            false_negatives += 1
            print(f"  ❌ FALSE NEGATIVE: \"{prompt[:60]}...\"")
            print(f"     Expected: {item.get('expected_rules', [])}")

    # Load benign prompts if available
    if benign_path and benign_path.exists():
        print("\n🧪 Running false-positive validation on benign prompts...")
        with open(benign_path) as f:
            benign = json.load(f)

        benign_fps = 0
        for item in benign:
            prompt = item["prompt"]
            matched = [r["id"] for r in rules if match_rule(r, prompt)]
            if matched:
                benign_fps += 1
                print(f"  ❌ FALSE POSITIVE: \"{prompt[:60]}...\"")
                print(f"     Matched: {matched}")

        print(f"\n  Benign false positives: {benign_fps}/{len(benign)}")

    # Metrics
    total = true_positives + false_negatives + true_negatives + false_positives
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "=" * 60)
    print("📊 RESULTS")
    print("=" * 60)
    print(f"  Total test prompts:  {total}")
    print(f"  True Positives:      {true_positives}")
    print(f"  True Negatives:      {true_negatives}")
    print(f"  False Positives:     {false_positives}")
    print(f"  False Negatives:     {false_negatives}")
    print(f"  Precision:           {precision:.2%}")
    print(f"  Recall:              {recall:.2%}")
    print(f"  F1 Score:            {f1:.2%}")
    print("=" * 60)

    # Exit code
    if f1 < 0.80:
        print("\n⚠ F1 score below 80% threshold — review rules")
        return 1
    else:
        print("\n✅ All checks passed")
        return 0


if __name__ == "__main__":
    base = Path(__file__).parent.parent
    rules_dir = base / "rules"
    corpus_path = base / "tests" / "test_corpus.json"
    benign_path = base / "tests" / "benign_prompts.json"

    exit_code = validate(rules_dir, corpus_path, benign_path)
    sys.exit(exit_code)
