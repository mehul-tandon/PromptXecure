#!/usr/bin/env python3
"""
PromptXecure — ML Classifier Training Script

Trains an XGBoost classifier on top of Sentence-Transformer embeddings for
prompt injection detection.

Usage:
    # From the promptxecure-core/ directory:
    uv run python scripts/train_classifier.py
    uv run python scripts/train_classifier.py --corpus ../../custom_data.json

Outputs:
    data/model/classifier.joblib   — Trained sklearn Pipeline (scaler + XGB)
    data/model/classifier.sha256   — SHA-256 hash for integrity verification

Dependencies (already in pyproject.toml):
    scikit-learn, xgboost, sentence-transformers, joblib, numpy
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path

import joblib
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("train_classifier")

# Project paths
SCRIPT_DIR = Path(__file__).resolve().parent
CORE_DIR = SCRIPT_DIR.parent
RULES_DIR = CORE_DIR.parent / "promptxecure-rules"
DEFAULT_CORPUS = RULES_DIR / "tests" / "test_corpus.json"
DEFAULT_BENIGN = RULES_DIR / "tests" / "benign_prompts.json"
DEFAULT_OUTPUT = CORE_DIR / "data" / "model"


# ── Data loading ─────────────────────────────────────────────────────────────

def load_corpus(corpus_path: Path, benign_path: Path) -> tuple[list[str], list[int]]:
    """Load labelled prompts from JSON files.

    Returns:
        (texts, labels) where label 1 = malicious, 0 = benign.
    """
    texts: list[str] = []
    labels: list[int] = []

    # Load malicious corpus
    if corpus_path.exists():
        with corpus_path.open() as f:
            for entry in json.load(f):
                texts.append(entry["prompt"])
                labels.append(1)
        logger.info(f"Loaded {corpus_path.name}: {sum(l == 1 for l in labels)} malicious prompts")
    else:
        logger.warning(f"Corpus not found at {corpus_path}")

    n_malicious = len(texts)

    # Load benign prompts
    if benign_path.exists():
        with benign_path.open() as f:
            data = json.load(f)
            # Handle both list-of-strings and list-of-dicts format
            for entry in data:
                if isinstance(entry, str):
                    texts.append(entry)
                else:
                    texts.append(entry.get("prompt", entry.get("text", "")))
                labels.append(0)
        logger.info(f"Loaded {benign_path.name}: {len(texts) - n_malicious} benign prompts")
    else:
        logger.warning(f"Benign prompts not found at {benign_path} — adding synthetic benign prompts")
        synthetic_benign = [
            "What is machine learning and how does it work?",
            "Can you explain the difference between TCP and UDP?",
            "Write a Python function to sort a list of numbers.",
            "What are the best practices for REST API design?",
            "How does HTTPS ensure secure communication?",
            "Explain the concept of recursion with an example.",
            "What is the difference between SQL and NoSQL databases?",
            "How do I implement pagination in a FastAPI app?",
            "Summarize the main points of this article about climate change.",
            "Can you help me write a cover letter for a software engineer position?",
            "What are some good Python libraries for data analysis?",
            "How do I center a div in CSS?",
            "Explain the CAP theorem in distributed systems.",
            "What are the benefits of containerization with Docker?",
            "How does gradient descent work in neural networks?",
            "Write a SQL query to find the top 5 customers by revenue.",
            "What is the difference between a stack and a queue?",
            "How do async/await work in Python?",
            "Explain the SOLID principles of object-oriented design.",
            "What is semantic versioning and why is it important?",
        ]
        texts.extend(synthetic_benign)
        labels.extend([0] * len(synthetic_benign))

    return texts, labels


# ── Embedding generation ──────────────────────────────────────────────────────

def generate_embeddings(texts: list[str], batch_size: int = 64) -> np.ndarray:
    """Generate sentence embeddings using all-MiniLM-L6-v2."""
    from sentence_transformers import SentenceTransformer

    logger.info("Loading sentence-transformer model: all-MiniLM-L6-v2 ...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    logger.info(f"Generating embeddings for {len(texts)} prompts (batch_size={batch_size})...")
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=True,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    logger.info(f"Embeddings shape: {embeddings.shape}")
    return embeddings


# ── Model training ────────────────────────────────────────────────────────────

def train_xgb_pipeline(X: np.ndarray, y: np.ndarray) -> object:
    """Build and train a StandardScaler + XGBoost pipeline."""
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from xgboost import XGBClassifier

    logger.info("Building XGBoost pipeline ...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    # Cross-validation
    logger.info("Running 5-fold cross-validation ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(pipeline, X, y, cv=cv, scoring="f1", n_jobs=-1)
    logger.info(f"Cross-val F1: {scores.mean():.4f} ± {scores.std():.4f}")

    # Fit on full dataset
    logger.info("Fitting on full dataset ...")
    pipeline.fit(X, y)

    return pipeline


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(pipeline: object, X: np.ndarray, y: np.ndarray) -> dict:
    """Print and return evaluation metrics."""
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        roc_auc_score,
    )

    y_pred = pipeline.predict(X)
    y_prob = pipeline.predict_proba(X)[:, 1]

    report = classification_report(y, y_pred, target_names=["benign", "malicious"])
    cm = confusion_matrix(y, y_pred)
    auc = roc_auc_score(y, y_prob)

    logger.info(f"\n{'─' * 50}\nClassification Report (train set):\n{report}")
    logger.info(f"Confusion Matrix:\n{cm}")
    logger.info(f"ROC-AUC: {auc:.4f}")

    return {"roc_auc": auc, "confusion_matrix": cm.tolist(), "report": report}


# ── Saving ────────────────────────────────────────────────────────────────────

def save_model(pipeline: object, output_dir: Path) -> Path:
    """Save model + SHA-256 hash to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "classifier.joblib"
    hash_path = output_dir / "classifier.sha256"

    logger.info(f"Saving model to {model_path} ...")
    joblib.dump(pipeline, model_path, compress=3)

    # Compute and store SHA-256
    sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    hash_path.write_text(sha256)
    logger.info(f"SHA-256: {sha256}")
    logger.info(f"Hash saved to {hash_path}")

    return model_path


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Train PromptXecure ML classifier")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="Path to malicious prompts JSON")
    parser.add_argument("--benign", type=Path, default=DEFAULT_BENIGN, help="Path to benign prompts JSON")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output directory for model artifacts")
    parser.add_argument("--batch-size", type=int, default=64, help="Embedding batch size")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("PromptXecure ML Classifier Training")
    logger.info("=" * 60)

    # Load data
    texts, labels = load_corpus(args.corpus, args.benign)
    logger.info(f"Total samples: {len(texts)} "
                f"(malicious={sum(labels)}, benign={len(labels) - sum(labels)})")

    if len(texts) < 10:
        logger.error("Not enough training data. Need at least 10 samples.")
        sys.exit(1)

    # Generate embeddings
    X = generate_embeddings(texts, batch_size=args.batch_size)
    y = np.array(labels, dtype=int)

    # Train
    pipeline = train_xgb_pipeline(X, y)

    # Evaluate
    evaluate(pipeline, X, y)

    # Save
    model_path = save_model(pipeline, args.output)
    logger.info(f"\n✓ Classifier trained and saved to: {model_path}")
    logger.info("Run `make dev-api` to start the API with the new model.")


if __name__ == "__main__":
    main()
