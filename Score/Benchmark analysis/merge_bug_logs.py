#!/usr/bin/env python3
"""Merge all individual bug log CSV files into a single ground truth CSV"""

import os
import csv
import glob
from collections import defaultdict

def merge_bug_logs(buggy_dir='buggy', output_file='merged_bug_logs.csv'):
    """
    Merge all BugLog_*.csv files into a single ground truth CSV
    
    Output format: bug_id,contract,line,bug_type,approach
    """
    
    bug_types = [
        'Re-entrancy',
        'Timestamp-Dependency',
        'Unchecked-Send',
        'Unhandled-Exceptions',
        'TOD',
        'Overflow-Underflow',
        'tx.origin'
    ]
    
    all_entries = []
    bug_id = 1
    
    print("Merging bug logs from all vulnerability types...")
    
    for bug_type in bug_types:
        bug_type_dir = os.path.join(buggy_dir, bug_type)
        if not os.path.exists(bug_type_dir):
            print(f"Warning: Directory not found: {bug_type_dir}")
            continue
        
        # Find all BugLog CSV files
        csv_files = glob.glob(os.path.join(bug_type_dir, "BugLog_*.csv"))
        print(f"\n{bug_type}: Found {len(csv_files)} bug log files")
        
        for csv_file in sorted(csv_files):
            # Extract contract number from filename (e.g., BugLog_1.csv -> 1)
            basename = os.path.basename(csv_file)
            contract_num = basename.replace('BugLog_', '').replace('.csv', '')
            contract_name = f"buggy_{contract_num}.sol"
            
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='replace') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        # Handle potential encoding issues in bug type field
                        bug_type_from_csv = row.get('bug type', '').strip()
                        # Replace encoded characters (e.g., Re+AC0-entrancy -> Re-entrancy)
                        bug_type_clean = bug_type_from_csv.replace('+AC0-', '-')
                        
                        # Use directory name as authoritative bug type if mismatch
                        if bug_type_clean != bug_type:
                            bug_type_clean = bug_type
                        
                        line_num = row.get('loc', '').strip()
                        approach = row.get('approach', 'code snippet injection').strip()
                        
                        if line_num:
                            try:
                                line_num = int(line_num)
                                all_entries.append({
                                    'bug_id': bug_id,
                                    'contract': contract_name,
                                    'line': line_num,
                                    'bug_type': bug_type_clean,
                                    'approach': approach
                                })
                                bug_id += 1
                            except ValueError:
                                print(f"  Warning: Invalid line number '{line_num}' in {csv_file}")
            
            except Exception as e:
                print(f"  Error processing {csv_file}: {e}")
    
    # Write merged CSV
    print(f"\nWriting merged ground truth to: {output_file}")
    with open(output_file, 'w', newline='') as f:
        fieldnames = ['bug_id', 'contract', 'line', 'bug_type', 'approach']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_entries)
    
    # Print statistics
    print(f"\n{'='*60}")
    print(f"MERGED GROUND TRUTH STATISTICS")
    print(f"{'='*60}")
    print(f"Total bug instances: {len(all_entries)}")
    
    # Count by bug type
    by_type = defaultdict(int)
    contracts_by_type = defaultdict(set)
    
    for entry in all_entries:
        by_type[entry['bug_type']] += 1
        contracts_by_type[entry['bug_type']].add(entry['contract'])
    
    print(f"\nBreakdown by vulnerability type:")
    print(f"  {'Type':<25} {'Bugs':>8} {'Contracts':>12}")
    print(f"  {'-'*25} {'-'*8} {'-'*12}")
    
    for bug_type in bug_types:
        if bug_type in by_type:
            print(f"  {bug_type:<25} {by_type[bug_type]:>8} {len(contracts_by_type[bug_type]):>12}")
    
    print(f"{'='*60}")
    print(f"\nGround truth file created: {output_file}")
    
    return output_file

if __name__ == '__main__':
    merge_bug_logs()
