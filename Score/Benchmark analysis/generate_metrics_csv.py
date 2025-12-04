import json
import csv
from collections import defaultdict

def load_comparison_results(json_path):
    """Load the comparison results from JSON"""
    with open(json_path, 'r') as f:
        return json.load(f)

def generate_metrics_by_bug_type(comparison_data, output_csv):
    """Generate metrics CSV grouped by bug type"""
    
    # Extract details
    tp_list = comparison_data['details']['TP']
    fp_list = comparison_data['details']['FP']
    fn_list = comparison_data['details']['FN']
    
    # Group by bug type
    bug_types = defaultdict(lambda: {'TP': 0, 'FP': 0, 'FN': 0})
    
    for tp in tp_list:
        bug_types[tp['bug_type']]['TP'] += 1
    
    for fp in fp_list:
        bug_types[fp['bug_type']]['FP'] += 1
    
    for fn in fn_list:
        bug_types[fn['bug_type']]['FN'] += 1
    
    # Calculate metrics for each bug type
    metrics = []
    for bug_type in sorted(bug_types.keys()):
        tp = bug_types[bug_type]['TP']
        fp = bug_types[bug_type]['FP']
        fn = bug_types[bug_type]['FN']
        tn = 0  # Not applicable for this dataset
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        metrics.append({
            'Bug_Type': bug_type,
            'TP': tp,
            'FP': fp,
            'TN': tn,
            'FN': fn,
            'Precision': round(precision, 4),
            'Recall': round(recall, 4),
            'F1_Score': round(f1, 4)
        })
    
    # Add overall metrics
    total_tp = sum(m['TP'] for m in metrics)
    total_fp = sum(m['FP'] for m in metrics)
    total_fn = sum(m['FN'] for m in metrics)
    
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0
    
    metrics.append({
        'Bug_Type': 'Overall',
        'TP': total_tp,
        'FP': total_fp,
        'TN': 0,
        'FN': total_fn,
        'Precision': round(overall_precision, 4),
        'Recall': round(overall_recall, 4),
        'F1_Score': round(overall_f1, 4)
    })
    
    # Write CSV
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['Bug_Type', 'TP', 'FP', 'TN', 'FN', 'Precision', 'Recall', 'F1_Score'])
        writer.writeheader()
        writer.writerows(metrics)
    
    print(f"✓ Generated: {output_csv}")
    return metrics

def save_detail_csv(items, output_csv, columns):
    """Save TP/FP/FN details to CSV"""
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(items)
    print(f"✓ Generated: {output_csv}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate metrics CSV from comparison results')
    parser.add_argument('--input', default='ground_truth_comparison.json', help='Input JSON file')
    parser.add_argument('--prefix', default='deepseek', help='Output file prefix')
    args = parser.parse_args()
    
    print(f"Loading comparison results from: {args.input}")
    data = load_comparison_results(args.input)
    
    # Generate metrics by bug type
    metrics_csv = f"{args.prefix}_metrics_by_bug_type.csv"
    metrics = generate_metrics_by_bug_type(data, metrics_csv)
    
    # Save TP details
    tp_csv = f"{args.prefix}_true_positives.csv"
    save_detail_csv(
        data['details']['TP'],
        tp_csv,
        ['contract', 'bug_type', 'llm_line', 'truth_line', 'diff']
    )
    
    # Save FP details
    fp_csv = f"{args.prefix}_false_positives.csv"
    save_detail_csv(
        data['details']['FP'],
        fp_csv,
        ['contract', 'bug_type', 'line']
    )
    
    # Save FN details
    fn_csv = f"{args.prefix}_false_negatives.csv"
    save_detail_csv(
        data['details']['FN'],
        fn_csv,
        ['contract', 'bug_type', 'line']
    )
    
    print("\n" + "="*70)
    print("SUMMARY METRICS")
    print("="*70)
    for m in metrics:
        if m['Bug_Type'] == 'Overall':
            print(f"\n{m['Bug_Type']:25s} | TP: {m['TP']:4d} | FP: {m['FP']:4d} | FN: {m['FN']:5d}")
            print(f"{'':25s} | Precision: {m['Precision']:.2%} | Recall: {m['Recall']:.2%} | F1: {m['F1_Score']:.4f}")
    print("="*70)

if __name__ == '__main__':
    main()
