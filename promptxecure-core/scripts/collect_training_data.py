#!/usr/bin/env python3
"""
PromptXecure — Langfuse Training Data Collector

Fetches PromptXecure traces from Langfuse and builds labeled training data
for the ML classifier.  Only uses high-confidence labels:
  - blocked  → label 1  (malicious)
  - passed   → label 0  (benign, only when risk_score < 0.25)

Usage:
    # From the promptxecure-core/ directory:
    uv run python scripts/collect_training_data.py
    uv run python scripts/collect_training_data.py --limit 500 --retrain

Options:
    --limit      Max traces to fetch from Langfuse (default: 200)
    --min-risk   Min risk_score for a blocked trace to be included (default: 0.7)
    --max-benign Max risk_score for a passed trace to be labeled benign (default: 0.25)
    --output     Output corpus JSON path (default: auto-generated in rules/tests/)
    --retrain    Run training after collecting data
    --host       Langfuse host (default: http://localhost:3000)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("collect_training_data")

SCRIPT_DIR = Path(__file__).resolve().parent
CORE_DIR = SCRIPT_DIR.parent
RULES_DIR = CORE_DIR.parent / "promptxecure-rules"
CORPUS_PATH = RULES_DIR / "tests" / "test_corpus.json"
BENIGN_PATH = RULES_DIR / "tests" / "benign_prompts.json"


# ── Langfuse fetcher ──────────────────────────────────────────────────────────

def fetch_traces(
    host: str,
    public_key: str,
    secret_key: str,
    limit: int = 200,
) -> list[dict]:
    """Fetch PromptXecure traces from Langfuse via the Python SDK."""
    try:
        from langfuse import Langfuse
    except ImportError:
        logger.error("langfuse not installed. Run: uv add langfuse")
        return []

    lf = Langfuse(public_key=public_key, secret_key=secret_key, host=host, debug=False)

    logger.info(f"Fetching up to {limit} traces from {host} ...")
    all_traces = []
    page = 1
    per_page = 50

    while len(all_traces) < limit:
        batch = lf.get_traces(limit=min(per_page, limit - len(all_traces)), page=page)
        if not batch.data:
            break
        all_traces.extend(batch.data)
        if len(batch.data) < per_page:
            break
        page += 1

    # Filter to PromptXecure traces only (name starts with "analyze |" or "playground |")
    px_traces = [
        t for t in all_traces
        if t.name and (
            t.name.startswith("analyze |") or
            t.name.startswith("playground |")
        )
    ]

    logger.info(f"Fetched {len(all_traces)} total traces, {len(px_traces)} are PromptXecure traces")
    return px_traces


# ── Sample extractor ──────────────────────────────────────────────────────────

def extract_samples(
    traces: list,
    min_risk_for_malicious: float = 0.7,
    max_risk_for_benign: float = 0.25,
) -> tuple[list[dict], list[dict]]:
    """
    Extract (malicious_samples, benign_samples) from traces.

    A trace is usable only when:
      - Its input.prompt is available
      - Status and risk_score are extractable from the trace name or output

    Returns two lists in the format expected by the corpus JSON files.
    """
    malicious: list[dict] = []
    benign: list[dict] = []
    skipped = 0

    for trace in traces:
        # ── Extract prompt ─────────────────────────────────────────────────────
        prompt = None
        if trace.input and isinstance(trace.input, dict):
            prompt = trace.input.get("prompt")
        if not prompt or len(prompt.strip()) < 5:
            skipped += 1
            continue

        # ── Extract status / risk_score from trace name ────────────────────────
        # Name format: "analyze | BLOCKED   | risk=0.82 | jailbreak"
        status = None
        risk_score = None
        try:
            parts = trace.name.split("|")
            if len(parts) >= 3:
                status = parts[1].strip().lower()
                risk_part = parts[2].strip()
                risk_score = float(risk_part.replace("risk=", ""))
        except (IndexError, ValueError):
            pass

        # Fallback: read from trace output
        if (status is None or risk_score is None) and trace.output and isinstance(trace.output, dict):
            status = status or trace.output.get("status")
            risk_score = risk_score or trace.output.get("risk_score")

        if status is None or risk_score is None:
            skipped += 1
            continue

        # ── Extract categories ─────────────────────────────────────────────────
        categories = []
        try:
            parts = trace.name.split("|")
            if len(parts) >= 4:
                categories = [c.strip() for c in parts[3].split(",") if c.strip() and c.strip() != "none"]
        except Exception:
            pass

        sample = {
            "prompt": prompt,
            "trace_id": trace.id,
            "status": status,
            "risk_score": round(risk_score, 4),
            "categories": categories,
            "source": "langfuse",
            "collected_at": datetime.utcnow().isoformat(),
        }

        if status == "blocked" and risk_score >= min_risk_for_malicious:
            malicious.append({**sample, "label": "malicious", "expected_rules": categories})
        elif status == "passed" and risk_score <= max_risk_for_benign:
            benign.append({**sample, "label": "safe"})
        else:
            skipped += 1

    logger.info(f"Extracted {len(malicious)} malicious + {len(benign)} benign samples ({skipped} skipped)")
    return malicious, benign


# ── Merge with existing corpus ────────────────────────────────────────────────

def merge_into_corpus(
    new_malicious: list[dict],
    new_benign: list[dict],
    corpus_path: Path,
    benign_path: Path,
) -> tuple[int, int]:
    """Merge new samples into existing corpus files, deduplicating by prompt."""
    # Load existing
    existing_malicious: list[dict] = []
    existing_benign: list[dict] = []

    if corpus_path.exists():
        with corpus_path.open() as f:
            existing_malicious = json.load(f)
    if benign_path.exists():
        with benign_path.open() as f:
            existing_benign = json.load(f)

    # Dedup by prompt text
    existing_mal_prompts = {e["prompt"] for e in existing_malicious}
    existing_ben_prompts = {e["prompt"] for e in existing_benign}

    added_mal = 0
    for s in new_malicious:
        if s["prompt"] not in existing_mal_prompts:
            existing_malicious.append(s)
            existing_mal_prompts.add(s["prompt"])
            added_mal += 1

    added_ben = 0
    for s in new_benign:
        if s["prompt"] not in existing_ben_prompts:
            existing_benign.append(s)
            existing_ben_prompts.add(s["prompt"])
            added_ben += 1

    # Save
    with corpus_path.open("w") as f:
        json.dump(existing_malicious, f, indent=2)
    with benign_path.open("w") as f:
        json.dump(existing_benign, f, indent=2)

    logger.info(
        f"Corpus updated: +{added_mal} malicious (total {len(existing_malicious)}), "
        f"+{added_ben} benign (total {len(existing_benign)})"
    )
    return added_mal, added_ben


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Collect Langfuse traces as ML training data")
    parser.add_argument("--limit",      type=int,   default=200,                      help="Max traces to fetch")
    parser.add_argument("--min-risk",   type=float, default=0.7,                      help="Min risk for malicious label")
    parser.add_argument("--max-benign", type=float, default=0.25,                     help="Max risk for benign label")
    parser.add_argument("--retrain",    action="store_true",                           help="Retrain classifier after collecting")
    parser.add_argument("--host",       default=os.getenv("LANGFUSE_HOST", "http://localhost:3000"))
    parser.add_argument("--public-key", default=os.getenv("LANGFUSE_PUBLIC_KEY", ""))
    parser.add_argument("--secret-key", default=os.getenv("LANGFUSE_SECRET_KEY", ""))
    args = parser.parse_args()

    if not args.public_key or not args.secret_key:
        # Try loading from .env
        env_path = CORE_DIR.parent / "promptxecure-api" / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("LANGFUSE_PUBLIC_KEY="):
                    args.public_key = line.split("=", 1)[1].strip()
                elif line.startswith("LANGFUSE_SECRET_KEY="):
                    args.secret_key = line.split("=", 1)[1].strip()
                elif line.startswith("LANGFUSE_HOST=") and "localhost" in args.host:
                    args.host = line.split("=", 1)[1].strip()

    if not args.public_key or not args.secret_key:
        logger.error("LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are required")
        logger.error("Set them via --public-key / --secret-key flags, or in .env")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("PromptXecure — Langfuse Training Data Collection")
    logger.info("=" * 60)

    # Fetch traces
    traces = fetch_traces(
        host=args.host,
        public_key=args.public_key,
        secret_key=args.secret_key,
        limit=args.limit,
    )

    if not traces:
        logger.warning("No PromptXecure traces found. Run some /analyze requests first.")
        sys.exit(0)

    # Extract labeled samples
    malicious_samples, benign_samples = extract_samples(
        traces,
        min_risk_for_malicious=args.min_risk,
        max_risk_for_benign=args.max_benign,
    )

    if not malicious_samples and not benign_samples:
        logger.warning("No usable samples found in traces.")
        sys.exit(0)

    # Merge into corpus
    added_mal, added_ben = merge_into_corpus(
        malicious_samples, benign_samples, CORPUS_PATH, BENIGN_PATH
    )

    logger.info(f"\nSummary: +{added_mal} malicious, +{added_ben} benign added to corpus")

    # Optionally retrain
    if args.retrain and (added_mal > 0 or added_ben > 0):
        logger.info("\nRetraining classifier with updated corpus ...")
        train_script = SCRIPT_DIR / "train_classifier.py"
        import subprocess
        result = subprocess.run(
            [sys.executable, str(train_script)],
            capture_output=False,
        )
        if result.returncode != 0:
            logger.error("Retraining failed")
        else:
            logger.info("Retraining complete")
    elif args.retrain:
        logger.info("No new samples — skipping retraining")


if __name__ == "__main__":
    main()
