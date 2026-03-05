# promptxecure-rules

Versioned YAML attack signature database for PromptXecure.

## Rule Categories

| File | Category | Rules |
|---|---|---|
| `direct_injection.yml` | Instruction override, mode switching | 12 |
| `jailbreak.yml` | DAN, persona switch, restriction bypass | 12 |
| `authority_override.yml` | Admin impersonation, privilege escalation | 8 |
| `data_extraction.yml` | System prompt extraction, probing | 10 |
| `delimiter_injection.yml` | Template tokens, XML tags, markers | 7 |
| `obfuscation.yml` | Base64, leetspeak, character evasion | 10 |
| `pii_leakage.yml` | Emails, SSNs, credit cards, credentials | 8 |
| `multi_turn.yml` | Progressive escalation, trust exploit | 6 |
| `indirect_injection.yml` | RAG poisoning, document injection | 8 |

## Rule Format

```yaml
rules:
  - id: DI001          # Unique ID: [CATEGORY_PREFIX][NUMBER]
    pattern: "regex"    # Regex pattern (for type: regex)
    keywords: [...]     # Keyword list (for type: keyword_any/keyword_all)
    type: regex         # regex | keyword_any | keyword_all | fuzzy
    severity: 0.95      # 0.0 (benign) to 1.0 (critical)
    category: string    # Threat classification
    description: string # Human-readable explanation
    flags: "i"          # Regex flags: i=case-insensitive, m=multiline
    enabled: true       # Toggle rule on/off
```

## Validation

```bash
cd promptxecure-rules
pip install pyyaml   # or: uv add pyyaml
python tests/validate_rules.py
```
