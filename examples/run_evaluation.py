#!/usr/bin/env python3
"""
Run the full evaluation suite for Prompt Shield.

This demonstrates how to evaluate detection accuracy against
known attack patterns and benign content.
"""

from prompt_shield import PromptShieldPipeline, Config
from prompt_shield.evaluation import (
    Evaluator,
    get_indirect_injection_suite,
    get_direct_injection_suite,
    get_benign_content_suite,
    get_all_test_suites,
)


def main():
    print("=" * 70)
    print("PROMPT SHIELD EVALUATION")
    print("=" * 70)
    
    # Initialize with default configuration
    pipeline = PromptShieldPipeline()
    evaluator = Evaluator(pipeline)
    
    # Run full evaluation
    print("\n## Running full evaluation suite...")
    evaluator.print_report()
    
    # Get detailed breakdown by category
    print("\n## Category Breakdown")
    print("-" * 50)
    
    indirect_suite = get_indirect_injection_suite()
    results, metrics = evaluator.evaluate_suite(indirect_suite)
    
    category_breakdown = evaluator.get_category_breakdown(results)
    
    for category, cat_metrics in sorted(category_breakdown.items()):
        print(f"\n### {category}")
        print(f"  Total: {cat_metrics.total_cases}")
        print(f"  Detection Rate: {cat_metrics.detection_rate:.1%}")
        print(f"  False Positives: {cat_metrics.false_positives}")
    
    # Show detailed failures
    print("\n## Detailed Failure Analysis")
    print("-" * 50)
    
    failures = [r for r in results if not r.is_correct]
    
    if failures:
        for fail in failures:
            print(f"\n### {fail.test_case.name}")
            print(f"  Category: {fail.test_case.category}")
            print(f"  Expected: {'Malicious' if fail.test_case.is_malicious else 'Benign'}")
            print(f"  Detected: {'Malicious' if fail.detected_as_malicious else 'Benign'}")
            print(f"  Risk Level: {fail.detected_risk_level.value}")
            print(f"  Content: {fail.test_case.content[:100]}...")
            
            if fail.detection_matches:
                print(f"  Matches: {len(fail.detection_matches)}")
                for match in fail.detection_matches[:3]:
                    print(f"    - {match['attack_type']}: {match['confidence']:.1%}")
    else:
        print("\n  No failures! Perfect detection.")
    
    # Compare configurations
    print("\n\n## Configuration Comparison")
    print("-" * 50)
    
    configs = {
        "Default": Config.default(),
        "Strict": Config.strict(),
        "Permissive": Config.permissive(),
    }
    
    for config_name, config in configs.items():
        pipeline = PromptShieldPipeline(config)
        evaluator = Evaluator(pipeline)
        
        all_results = evaluator.evaluate_all()
        
        total_tp = sum(m.true_positives for _, (_, m) in all_results.items())
        total_fp = sum(m.false_positives for _, (_, m) in all_results.items())
        total_fn = sum(m.false_negatives for _, (_, m) in all_results.items())
        total_tn = sum(m.true_negatives for _, (_, m) in all_results.items())
        
        total = total_tp + total_fp + total_fn + total_tn
        accuracy = (total_tp + total_tn) / total if total > 0 else 0
        detection_rate = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        fp_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0
        
        print(f"\n### {config_name} Configuration")
        print(f"  Accuracy:       {accuracy:.1%}")
        print(f"  Detection Rate: {detection_rate:.1%}")
        print(f"  FP Rate:        {fp_rate:.1%}")
    
    print("\n" + "=" * 70)
    print("Evaluation complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
