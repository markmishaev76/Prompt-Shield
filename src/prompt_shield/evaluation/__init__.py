"""
Evaluation framework for Prompt Shield.

Provides comprehensive testing for indirect prompt injection detection,
with a focus on real-world scenarios that occur in tool outputs.
"""

from prompt_shield.evaluation.test_cases import (
    TestCase,
    TestSuite,
    get_indirect_injection_suite,
    get_direct_injection_suite,
    get_benign_content_suite,
    get_all_test_suites,
)
from prompt_shield.evaluation.evaluator import (
    Evaluator,
    EvaluationResult,
    EvaluationMetrics,
)

__all__ = [
    "TestCase",
    "TestSuite",
    "get_indirect_injection_suite",
    "get_direct_injection_suite",
    "get_benign_content_suite",
    "get_all_test_suites",
    "Evaluator",
    "EvaluationResult",
    "EvaluationMetrics",
]
