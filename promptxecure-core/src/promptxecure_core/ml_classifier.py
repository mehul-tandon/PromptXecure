"""
ML Classifier — Semantic prompt injection detection using embeddings + XGBoost.

Uses Sentence-Transformers for embedding generation and XGBoost for
classification. Falls back to a heuristic scorer if no trained model is available.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

from promptxecure_core.config import PipelineConfig
from promptxecure_core.models import LayerResult, ThreatResult
from promptxecure_core.utils import elapsed_ms, timer_ms

logger = logging.getLogger(__name__)


# Heuristic keywords and their weights for fallback scoring
HEURISTIC_SIGNALS = {
    "ignore": 0.3, "disregard": 0.35, "forget": 0.3,
    "override": 0.35, "bypass": 0.35, "jailbreak": 0.5,
    "DAN": 0.5, "unrestricted": 0.4, "unfiltered": 0.4,
    "system prompt": 0.45, "previous instructions": 0.45,
    "no restrictions": 0.4, "admin": 0.2, "developer mode": 0.4,
    "pretend": 0.25, "roleplay": 0.2, "act as": 0.15,
    "reveal": 0.25, "repeat everything": 0.35, "base64": 0.2,
    "execute": 0.2, "hack": 0.25, "exploit": 0.3,
    "malicious": 0.3, "harmful": 0.25, "dangerous": 0.2,
}


class MLClassifier:
    """Embedding-based ML classifier for prompt injection detection."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self._model = None
        self._classifier = None
        self._loaded = False

    def load_model(self, model_path: str | Path = "") -> bool:
        """
        Load the trained classifier and embedding model.
        Returns True if loaded successfully, False if falling back to heuristics.
        """
        model_path = Path(model_path) if model_path else Path(self.config.model_path)

        # Try loading trained classifier
        classifier_path = model_path / "classifier.joblib" if model_path.is_dir() else model_path
        if classifier_path.exists():
            try:
                import joblib
                self._classifier = joblib.load(classifier_path)
                logger.info(f"Loaded trained classifier from {classifier_path}")
            except Exception as e:
                logger.warning(f"Failed to load classifier: {e}")

        # Try loading embedding model
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._loaded = True
            logger.info("Loaded sentence-transformer model: all-MiniLM-L6-v2")
        except Exception as e:
            logger.warning(f"Sentence-transformers not available, using heuristic fallback: {e}")
            self._loaded = False

        return self._loaded

    def evaluate(self, text: str) -> LayerResult:
        """
        Evaluate a prompt using the ML classifier.
        Falls back to heuristic scoring if ML model is not loaded.
        """
        start = timer_ms()

        if self._loaded and self._model is not None:
            result = self._ml_classify(text)
        else:
            result = self._heuristic_classify(text)

        result.latency_ms = elapsed_ms(start)
        return result

    def _ml_classify(self, text: str) -> LayerResult:
        """Run full ML classification with embeddings + trained model."""
        try:
            # Generate embedding
            embedding = self._model.encode([text], show_progress_bar=False)

            if self._classifier is not None:
                # Use trained classifier
                prediction = self._classifier.predict(embedding)[0]
                probabilities = self._classifier.predict_proba(embedding)[0]
                max_prob = float(np.max(probabilities))

                # prediction is int (0=benign, 1=malicious) from XGBoost
                is_threat = int(prediction) != 0
                category = "ml_injection" if is_threat else "benign"
                score = max_prob if is_threat else 1.0 - max_prob

            else:
                # No trained classifier — use embedding similarity heuristic
                score = self._embedding_heuristic(embedding[0])
                is_threat = score > self.config.ml_confidence_threshold
                category = "suspicious" if is_threat else "benign"

            threats = []
            if is_threat:
                threats.append(ThreatResult(
                    rule_id="ML001",
                    type=category,
                    layer="ml_classifier",
                    confidence=score,
                    description=f"XGBoost+embeddings classifier: injection detected (confidence={score:.2f})",
                    severity=score,
                ))

            return LayerResult(
                name="ml_classifier",
                triggered=is_threat,
                score=score,
                category=category,
                matches=1 if is_threat else 0,
                threats=threats,
                metadata={"method": "ml" if self._classifier is not None else "heuristic", "model": "all-MiniLM-L6-v2"},
            )

        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return self._heuristic_classify(text)

    def _embedding_heuristic(self, embedding: np.ndarray) -> float:
        """Simple heuristic based on embedding properties when no classifier is trained."""
        # Use embedding norm and variance as rough indicators
        norm = float(np.linalg.norm(embedding))
        variance = float(np.var(embedding))
        # Normalize to 0-1 range (empirical thresholds)
        score = min(1.0, max(0.0, (norm - 3.0) / 10.0 + variance * 50))
        return score

    def _heuristic_classify(self, text: str) -> LayerResult:
        """Fallback: keyword-weighted heuristic scoring."""
        text_lower = text.lower()
        total_weight = 0.0
        matched_signals = []

        for keyword, weight in HEURISTIC_SIGNALS.items():
            if keyword.lower() in text_lower:
                total_weight += weight
                matched_signals.append(keyword)

        # Normalize score (cap at 1.0)
        score = min(1.0, total_weight)
        is_threat = score > self.config.ml_confidence_threshold

        threats = []
        if is_threat:
            threats.append(ThreatResult(
                rule_id="ML_HEURISTIC",
                type="heuristic_detection",
                layer="ml_classifier",
                confidence=score,
                description=f"Heuristic signals: {', '.join(matched_signals[:5])}",
                pattern_matched=", ".join(matched_signals[:3]),
                severity=score,
            ))

        return LayerResult(
            name="ml_classifier",
            triggered=is_threat,
            score=score,
            category="heuristic_detection" if is_threat else "benign",
            matches=len(matched_signals),
            threats=threats,
            metadata={"method": "heuristic", "signals": matched_signals},
        )
