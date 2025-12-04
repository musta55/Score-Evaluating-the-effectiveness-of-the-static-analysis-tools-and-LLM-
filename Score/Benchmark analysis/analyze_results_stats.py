import csv
import os
import glob
from collections import defaultdict

def analyze_csvs(base_path):
    tools = ['Oyente', 'Smartcheck', 'Mythril', 'Manticore', 'Securify', 'Slither', 'DeepSeek', 'Llama3', 'llama3']
    
    stats = defaultdict(lambda: {'FN': defaultdict(int), 'FP': defaultdict(int)})
    
    # Analyze FNs
    fn_path = os.path.join(base_path, 'FNs')
    for tool in tools:
        pattern = os.path.join(fn_path, f'{tool}_FNs.csv')
        files = glob.glob(pattern)
        if not files:
            continue
            
        filename = files[0]
        try:
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    bug_type = row.get('BugType', 'Unknown')
                    try:
                        count = int(row.get('FalseNegatives', 0))
                        stats[tool]['FN'][bug_type] = count
                        stats[tool]['FN']['Total'] += count
                    except ValueError:
                        pass
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    # Analyze FPs
    fp_path = os.path.join(base_path, 'FPs')
    for tool in tools:
        pattern = os.path.join(fp_path, f'{tool}_FPs.csv')
        files = glob.glob(pattern)
        if not files:
            continue
            
        filename = files[0]
        try:
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    bug_type = row.get('BugType', 'Unknown')
                    try:
                        count = int(row.get('FalsePositives', 0))
                        stats[tool]['FP'][bug_type] = count
                        stats[tool]['FP']['Total'] += count
                    except ValueError:
                        pass
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    return stats

def print_stats(stats):
    print("Tool Analysis Statistics (Based on FNs/FPs summary CSVs)")
    print("=" * 60)
    
    for tool in sorted(stats.keys()):
        print(f"\nTool: {tool}")
        print("-" * 30)
        
        fns = stats[tool]['FN']
        fps = stats[tool]['FP']
        
        print(f"False Negatives (Missed Bugs): {fns['Total']}")
        for bug, count in fns.items():
            if bug != 'Total':
                print(f"  - {bug}: {count}")
                
        print(f"False Positives (Wrong Alarms): {fps['Total']}")
        for bug, count in fps.items():
            if bug != 'Total':
                print(f"  - {bug}: {count}")

if __name__ == "__main__":
    # Assuming running from project root
    base_path = "Score- Benchmark"
    stats = analyze_csvs(base_path)
    print_stats(stats)
