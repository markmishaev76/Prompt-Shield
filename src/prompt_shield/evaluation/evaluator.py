"""
Evaluator for measuring Prompt Shield performance.

Computes metrics including:
- Detection rate (recall) for malicious content
- False positive rate for benign content
- Precision, F1 score
- Per-category breakdown
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from prompt_shield.types import (
    ContentSource,
    RiskLevel,
)
from prompt_shield.pipeline import PromptShieldPipeline
from prompt_shield.config import Config
from prompt_shield.evaluation.test_cases import TestCase, TestSuite

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """Result of evaluating a single test case."""
    
    test_case: TestCase
    
    # Detection outcome
    detected_as_malicious: bool
    detected_risk_level: RiskLevel
    
    # Correctness
    is_correct: bool
    is_true_positive: bool = False
    is_true_negative: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False
    
    # Details
    detection_matches: List = field(default_factory=list)
    processing_time_ms: float = 0.0
    

@dataclass
class EvaluationMetrics:
    """Aggregated metrics from evaluation."""
    
    # Basic counts
    total_cases: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    # Derived metrics
    @property
    def accuracy(self) -> float:
        if self.total_cases == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / self.total_cases
    
    @property
    def precision(self) -> float:
        total_predicted_positive = self.true_positives + self.false_positives
        if total_predicted_positive == 0:
            return 0.0
        return self.true_positives / total_predicted_positive
    
    @property
    def recall(self) -> float:
        """Also known as detection rate or sensitivity."""
        total_actual_positive = self.true_positives + self.false_negatives
        if total_actual_positive == 0:
            return 0.0
        return self.true_positives / total_actual_positive
    
    @property
    def f1_score(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def false_positive_rate(self) -> float:
        total_actual_negative = self.true_negatives + self.false_positives
        if total_actual_negative == 0:
            return 0.0
        return self.false_positives / total_actual_negative
    
    @property
    def detection_rate(self) -> float:
        """Alias for recall - percentage of attacks detected."""
        return self.recall
    
    def to_dict(self) -> dict:
        return {
            "total_cases": self.total_cases,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "detection_rate": round(self.detection_rate, 4),
        }


class Evaluator:
    """
    Evaluator for measuring Prompt Shield detection performance.
    
    Example:
        >>> pipeline = PromptShieldPipeline()
        >>> evaluator = Evaluator(pipeline)
        >>> suite = get_indirect_injection_suite()
        >>> results, metrics = evaluator.evaluate_suite(suite)
        >>> print(f"Detection rate: {metrics.detection_rate:.1%}")
    """
    
    def __init__(
        self,
        pipeline: Optional[PromptShieldPipeline] = None,
        config: Optional[Config] = None,
    ):
        self.pipeline = pipeline or PromptShieldPipeline(config)
    
    def evaluate_case(self, test_case: TestCase) -> EvaluationResult:
        """Evaluate a single test case."""
        # Create source from test case
        source = ContentSource(
            source_type=test_case.content_type,
            author_trust_level=test_case.trust_level,
        )
        
        # Run through pipeline
        result = self.pipeline.process(test_case.content, source)
        
        # Determine detection outcome
        detected_as_malicious = not result.is_safe
        detected_risk_level = result.overall_risk
        
        # Determine correctness
        is_correct = detected_as_malicious == test_case.is_malicious
        
        # Categorize result
        is_true_positive = test_case.is_malicious and detected_as_malicious
        is_true_negative = not test_case.is_malicious and not detected_as_malicious
        is_false_positive = not test_case.is_malicious and detected_as_malicious
        is_false_negative = test_case.is_malicious and not detected_as_malicious
        
        # Get detection matches if available
        detection_matches = []
        if result.detection_result:
            detection_matches = [
                {
                    "attack_type": m.attack_type.value,
                    "confidence": m.confidence,
                    "pattern": m.pattern_name,
                }
                for m in result.detection_result.matches
            ]
        
        return EvaluationResult(
            test_case=test_case,
            detected_as_malicious=detected_as_malicious,
            detected_risk_level=detected_risk_level,
            is_correct=is_correct,
            is_true_positive=is_true_positive,
            is_true_negative=is_true_negative,
            is_false_positive=is_false_positive,
            is_false_negative=is_false_negative,
            detection_matches=detection_matches,
            processing_time_ms=result.total_processing_time_ms,
        )
    
    def evaluate_suite(
        self,
        suite: TestSuite,
    ) -> Tuple[List[EvaluationResult], EvaluationMetrics]:
        """
        Evaluate all test cases in a suite.
        
        Returns:
            Tuple of (individual results, aggregated metrics)
        """
        results: List[EvaluationResult] = []
        metrics = EvaluationMetrics()
        
        for test_case in suite:
            result = self.evaluate_case(test_case)
            results.append(result)
            
            # Update metrics
            metrics.total_cases += 1
            if result.is_true_positive:
                metrics.true_positives += 1
            elif result.is_true_negative:
                metrics.true_negatives += 1
            elif result.is_false_positive:
                metrics.false_positives += 1
            elif result.is_false_negative:
                metrics.false_negatives += 1
        
        return results, metrics
    
    def evaluate_all(
        self,
        suites: Optional[List[TestSuite]] = None,
    ) -> Dict[str, Tuple[List[EvaluationResult], EvaluationMetrics]]:
        """
        Evaluate multiple test suites.
        
        Returns:
            Dict mapping suite name to (results, metrics)
        """
        if suites is None:
            from prompt_shield.evaluation.test_cases import get_all_test_suites
            suites = get_all_test_suites()
        
        all_results = {}
        for suite in suites:
            results, metrics = self.evaluate_suite(suite)
            all_results[suite.name] = (results, metrics)
        
        return all_results
    
    def print_report(
        self,
        suites: Optional[List[TestSuite]] = None,
    ) -> None:
        """Print a formatted evaluation report."""
        all_results = self.evaluate_all(suites)
        
        print("\n" + "=" * 70)
        print("PROMPT SHIELD EVALUATION REPORT")
        print("=" * 70)
        
        overall_metrics = EvaluationMetrics()
        
        for suite_name, (results, metrics) in all_results.items():
            print(f"\n## {suite_name}")
            print("-" * 50)
            print(f"  Total cases:      {metrics.total_cases}")
            print(f"  True positives:   {metrics.true_positives}")
            print(f"  True negatives:   {metrics.true_negatives}")
            print(f"  False positives:  {metrics.false_positives}")
            print(f"  False negatives:  {metrics.false_negatives}")
            print(f"  Accuracy:         {metrics.accuracy:.1%}")
            print(f"  Precision:        {metrics.precision:.1%}")
            print(f"  Recall:           {metrics.recall:.1%}")
            print(f"  F1 Score:         {metrics.f1_score:.1%}")
            
            # Aggregate overall
            overall_metrics.total_cases += metrics.total_cases
            overall_metrics.true_positives += metrics.true_positives
            overall_metrics.true_negatives += metrics.true_negatives
            overall_metrics.false_positives += metrics.false_positives
            overall_metrics.false_negatives += metrics.false_negatives
            
            # Show failures
            failures = [r for r in results if not r.is_correct]
            if failures:
                print(f"\n  Failed cases ({len(failures)}):")
                for fail in failures[:5]:  # Show max 5
                    status = "FP" if fail.is_false_positive else "FN"
                    print(f"    [{status}] {fail.test_case.name}")
        
        print("\n" + "=" * 70)
        print("OVERALL METRICS")
        print("=" * 70)
        print(f"  Total cases:        {overall_metrics.total_cases}")
        print(f"  Detection rate:     {overall_metrics.detection_rate:.1%}")
        print(f"  False positive rate:{overall_metrics.false_positive_rate:.1%}")
        print(f"  Precision:          {overall_metrics.precision:.1%}")
        print(f"  F1 Score:           {overall_metrics.f1_score:.1%}")
        print("=" * 70 + "\n")
    
    def get_category_breakdown(
        self,
        results: List[EvaluationResult],
    ) -> Dict[str, EvaluationMetrics]:
        """Get metrics broken down by category."""
        by_category: Dict[str, EvaluationMetrics] = {}
        
        for result in results:
            category = result.test_case.category or "uncategorized"
            
            if category not in by_category:
                by_category[category] = EvaluationMetrics()
            
            metrics = by_category[category]
            metrics.total_cases += 1
            
            if result.is_true_positive:
                metrics.true_positives += 1
            elif result.is_true_negative:
                metrics.true_negatives += 1
            elif result.is_false_positive:
                metrics.false_positives += 1
            elif result.is_false_negative:
                metrics.false_negatives += 1
        
        return by_category
