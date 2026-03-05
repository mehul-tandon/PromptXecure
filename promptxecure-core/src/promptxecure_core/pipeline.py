"""
Pipeline Orchestrator — Chains all detection layers into a unified analysis.

This is the main entry point for the PromptXecure Core engine.
"""

from __future__ import annotations

import logging
from pathlib import Path

from promptxecure_core.config import PipelineConfig
from promptxecure_core.containment import ContainmentEngine
from promptxecure_core.ml_classifier import MLClassifier
from promptxecure_core.models import AnalysisResult, LayerResult
from promptxecure_core.output_validator import OutputValidator
from promptxecure_core.preprocessor import Preprocessor
from promptxecure_core.rule_engine import RuleEngine
from promptxecure_core.shadow_llm import ShadowLLM
from promptxecure_core.utils import elapsed_ms, timer_ms

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Main detection pipeline — orchestrates all layers.

    Usage:
        pipeline = Pipeline(rules_path="path/to/rules/")
        result = pipeline.analyze("some user prompt")
    """

    def __init__(
        self,
        config: PipelineConfig | None = None,
        rules_path: str | Path = "",
        model_path: str | Path = "",
    ):
        self.config = config or PipelineConfig()

        # Override paths if provided
        if rules_path:
            self.config.rules_path = str(rules_path)
        if model_path:
            self.config.model_path = str(model_path)

        # Initialize layers
        self.preprocessor = Preprocessor(self.config)
        self.rule_engine = RuleEngine(self.config)
        self.ml_classifier = MLClassifier(self.config)
        self.shadow_llm = ShadowLLM(self.config)
        self.output_validator = OutputValidator(self.config)
        self.containment = ContainmentEngine(self.config)

        # Load rules and models
        self._initialize()

    def _initialize(self):
        """Load rules and ML models at startup."""
        if self.config.rules_path:
            rules_loaded = self.rule_engine.load_rules(self.config.rules_path)
            logger.info(f"Pipeline initialized with {rules_loaded} rules")
        else:
            logger.warning("No rules path configured — YAML rule engine disabled")

        if self.config.ml_enabled:
            loaded = self.ml_classifier.load_model(self.config.model_path)
            if loaded:
                logger.info("ML classifier loaded successfully")
            else:
                logger.info("ML classifier using heuristic fallback")

    def analyze(self, prompt: str) -> AnalysisResult:
        """
        Run the full detection pipeline on a prompt.

        Steps:
        1. Preprocess (normalize, decode)
        2. YAML Rule Engine (pattern matching)
        3. ML Classifier (semantic analysis)
        4. Shadow LLM (safety review) — if enabled
        5. Aggregate risk scores
        6. Containment decision (pass/sanitize/block)
        """
        start = timer_ms()

        result = AnalysisResult(original_prompt=prompt)

        # Step 1: Preprocess
        preprocessed = self.preprocessor.preprocess(prompt)
        result.preprocessed_prompt = preprocessed

        if not preprocessed:
            result.processing_ms = elapsed_ms(start)
            return result

        # Validate length
        if not self.preprocessor.validate_length(preprocessed):
            logger.warning("Input exceeds length limits")
            result.risk_score = 0.8
            result.risk_level = self.containment.classify_risk(0.8)
            result.action = self.containment.determine_action(result.risk_level)
            result.processing_ms = elapsed_ms(start)
            return result

        # Step 2: YAML Rule Engine
        rule_result = self.rule_engine.evaluate(preprocessed)
        result.layers["yaml_rules"] = rule_result
        result.threats.extend(rule_result.threats)

        # Step 3: ML Classifier
        if self.config.ml_enabled:
            ml_result = self.ml_classifier.evaluate(preprocessed)
            result.layers["ml_classifier"] = ml_result
            result.threats.extend(ml_result.threats)

        # Step 4: Shadow LLM (only if previous layers flagged something, or always if configured)
        if self.config.shadow_llm_enabled:
            preliminary_score = self._aggregate_scores(result.layers)
            # Only invoke shadow LLM if there's some suspicion (saves cost/time)
            if preliminary_score >= self.config.risk_threshold_suspicious * 0.5:
                shadow_result = self.shadow_llm.evaluate(preprocessed)
                result.layers["shadow_llm"] = shadow_result
                result.threats.extend(shadow_result.threats)

        # Step 5: Aggregate risk scores
        result.risk_score = self._aggregate_scores(result.layers)

        # Step 6: Containment
        action, sanitized, risk_level = self.containment.contain(
            preprocessed, result.risk_score
        )
        result.risk_level = risk_level
        result.action = action
        result.sanitized_prompt = sanitized

        result.processing_ms = elapsed_ms(start)

        logger.info(
            f"Analysis complete: risk={result.risk_score:.2f} "
            f"level={result.risk_level.value} action={result.action.value} "
            f"threats={result.threat_count} time={result.processing_ms:.1f}ms"
        )

        return result

    def analyze_output(self, output: str) -> LayerResult:
        """
        Validate an LLM output for data leakage.
        Called AFTER the LLM generates a response.
        """
        return self.output_validator.evaluate(output)

    def _aggregate_scores(self, layers: dict[str, LayerResult]) -> float:
        """
        Aggregate risk scores from all detection layers.

        Uses weighted combination:
        - YAML rules: weight 0.40 (high precision, pattern-based)
        - ML classifier: weight 0.35 (semantic understanding)
        - Shadow LLM: weight 0.25 (creative attack detection)
        """
        weights = {
            "yaml_rules": 0.40,
            "ml_classifier": 0.35,
            "shadow_llm": 0.25,
        }

        total_weight = 0.0
        weighted_score = 0.0

        for layer_name, layer_result in layers.items():
            weight = weights.get(layer_name, 0.1)
            total_weight += weight

            if layer_result.triggered:
                # Use the max of score and a minimum trigger threshold
                score = max(layer_result.score, 0.5)
                weighted_score += weight * score
            else:
                weighted_score += weight * layer_result.score

        if total_weight == 0:
            return 0.0

        aggregated = weighted_score / total_weight

        # Boost score if multiple layers agree (ensemble agreement bonus)
        triggered_count = sum(1 for lr in layers.values() if lr.triggered)
        if triggered_count >= 2:
            aggregated = min(1.0, aggregated * 1.2)
        if triggered_count >= 3:
            aggregated = min(1.0, aggregated * 1.1)

        return min(1.0, aggregated)

    @property
    def status(self) -> dict:
        """Return pipeline status for health checks."""
        return {
            "rules_loaded": self.rule_engine.rule_count,
            "ml_enabled": self.config.ml_enabled,
            "shadow_llm_enabled": self.config.shadow_llm_enabled,
            "output_validation_enabled": self.config.output_validation_enabled,
            "thresholds": {
                "suspicious": self.config.risk_threshold_suspicious,
                "malicious": self.config.risk_threshold_malicious,
            },
        }
