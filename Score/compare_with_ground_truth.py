#!/usr/bin/env python3

import csv
import json
import argparse
from collections import defaultdict


def load_ground_truth(gt_csv_path):

    gt = []
    with open(gt_csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            contract = row.get('contract', '').strip()
            try:
                line = int(row.get('line', '0'))
            except Exception:
                line = 0
            bug_type = row.get('bug_type', '').strip()
            if contract and bug_type and line > 0:
                gt.append((contract, bug_type, line))
    return set(gt)


def load_llm_findings(llm_dir):
    findings = []
    for root, _, files in os.walk(llm_dir):
        for fn in files:
            if fn.endswith('.sol.json'):
                path = os.path.join(root, fn)
                try:
                    with open(path, 'r') as f:
                        obj = json.load(f)
                except Exception as e:
                    print(f"Warning: Could not parse {path}: {e}")
                    continue
                
                contract = obj.get('contract', '').strip()
                bug_type = obj.get('bug_type', '').strip()
                
                for fnd in obj.get('findings', []):
                    ln = fnd.get('line_number', 0)
                    try:
                        ln = int(ln)
                    except Exception:
                        ln = 0
                    
                    if contract and bug_type and ln > 0:
                        findings.append((contract, bug_type, ln))
    
    return findings


def compare(llm_findings, ground_truth, line_tolerance=2):
    gt_matched = set()
    tp = []
    fp = []
    
    # Group ground truth by (contract, bug_type) for faster lookup
    gt_by_key = defaultdict(list)
    for c, b, l in ground_truth:
        gt_by_key[(c, b)].append(l)
    
    # Check each LLM finding
    for contract, bug_type, ln in llm_findings:
        found_match = False
        
        # Look for matching ground truth within tolerance
        for truth_ln in gt_by_key.get((contract, bug_type), []):
            if abs(truth_ln - ln) <= line_tolerance:
                tp.append({
                    "contract": contract,
                    "bug_type": bug_type,
                    "llm_line": ln,
                    "truth_line": truth_ln,
                    "diff": ln - truth_ln
                })
                gt_matched.add((contract, bug_type, truth_ln))
                found_match = True
                break
        
        if not found_match:
            fp.append({
                "contract": contract,
                "bug_type": bug_type,
                "line": ln
            })
    
    # False negatives: ground-truth entries not matched by LLM
    fn = []
    for (c, b, l) in ground_truth:
        if (c, b, l) not in gt_matched:
            fn.append({
                "contract": c,
                "bug_type": b,
                "line": l
            })
    
    return {"TP": tp, "FP": fp, "FN": fn}


def compute_metrics(tp_count, fp_count, fn_count):
    if tp_count + fp_count > 0:
        precision = tp_count / (tp_count + fp_count)
    else:
        precision = 0.0
    
    if tp_count + fn_count > 0:
        recall = tp_count / (tp_count + fn_count)
    else:
        recall = 0.0
    
    if precision + recall > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = 0.0
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4)
    }


def main():
    parser = argparse.ArgumentParser(
        description='Compare LLM results with ground-truth CSV for FP/FN analysis'
    )
    parser.add_argument(
        '--llm-dir',
        default='tool_results/LLM/analyzed_buggy_contracts',
        help='LLM results directory (default: tool_results/LLM/analyzed_buggy_contracts)'
    )
    parser.add_argument(
        '--ground-truth',
        required=True,
        help='Ground truth CSV path (format: bug_id,contract,line,bug_type)'
    )
    parser.add_argument(
        '--tolerance',
        type=int,
        default=2,
        help='Line number tolerance for matching (default: 2)'
    )
    parser.add_argument(
        '--out',
        default='ground_truth_comparison.json',
        help='Summary output file (default: ground_truth_comparison.json)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print detailed FP/FN lists'
    )
    parser.add_argument(
        '--output-prefix',
        default='llm',
        help='Prefix for output CSV files (default: llm)'
    )
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading ground truth from: {args.ground_truth}")
    gt = load_ground_truth(args.ground_truth)
    print(f"  Loaded {len(gt)} ground truth entries")
    
    print(f"\nLoading LLM findings from: {args.llm_dir}")
    llm_findings = load_llm_findings(args.llm_dir)
    print(f"  Loaded {len(llm_findings)} LLM findings")
    
    # Compare
    print(f"\nComparing with line tolerance: ±{args.tolerance}")
    stats = compare(llm_findings, gt, args.tolerance)
    
    tp_count = len(stats["TP"])
    fp_count = len(stats["FP"])
    fn_count = len(stats["FN"])
    
    # Compute metrics
    metrics = compute_metrics(tp_count, fp_count, fn_count)
    
    # Build summary
    summary = {
        "configuration": {
            "llm_dir": args.llm_dir,
            "ground_truth": args.ground_truth,
            "line_tolerance": args.tolerance
        },
        "counts": {
            "total_llm_findings": len(llm_findings),
            "total_ground_truth": len(gt),
            "true_positives": tp_count,
            "false_positives": fp_count,
            "false_negatives": fn_count
        },
        "metrics": metrics,
        "details": stats
    }
    
    # Save to file
    with open(args.out, 'w') as fw:
        json.dump(summary, fw, indent=2)
    print(f"\n✓ Wrote summary to: {args.out}")
    
    # Print summary
    print("\n" + "="*60)
    print("COMPARISON SUMMARY")
    print("="*60)
    print(f"Total LLM Findings:    {len(llm_findings)}")
    print(f"Total Ground Truth:    {len(gt)}")
    print(f"\nTrue Positives (TP):   {tp_count}")
    print(f"False Positives (FP):  {fp_count}")
    print(f"False Negatives (FN):  {fn_count}")
    print(f"\nPrecision:             {metrics['precision']:.2%}")
    print(f"Recall:                {metrics['recall']:.2%}")
    print(f"F1 Score:              {metrics['f1_score']:.4f}")
    print("="*60)
    
    if args.verbose:
        print("\n" + "-"*60)
        print("FALSE POSITIVES (LLM detected, but not in ground truth):")
        print("-"*60)
        for fp in stats["FP"][:10]:  # Show first 10
            print(f"  {fp['contract']:20s} | {fp['bug_type']:20s} | Line {fp['line']}")
        if len(stats["FP"]) > 10:
            print(f"  ... and {len(stats['FP']) - 10} more")
        
        print("\n" + "-"*60)
        print("FALSE NEGATIVES (Ground truth missed by LLM):")
        print("-"*60)
        for fn in stats["FN"][:10]:  # Show first 10
            print(f"  {fn['contract']:20s} | {fn['bug_type']:20s} | Line {fn['line']}")
        if len(stats["FN"]) > 10:
            print(f"  ... and {len(stats['FN']) - 10} more")


if __name__ == '__main__':
    main()
