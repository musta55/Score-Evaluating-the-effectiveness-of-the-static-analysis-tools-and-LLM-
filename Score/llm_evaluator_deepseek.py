import os
import json
from string import Template
import time
import requests
from requests.exceptions import RequestException
from evaluation_helpers import (
    extract_contract_name,
    coerce_line_number,
    map_llm_to_subtypes,
    map_llm_to_severity,
    extract_context_from_code,
    extract_json_from_text
)

# Configuration
OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL = 'deepseek-r1:7b'  # DeepSeek-R1 reasoning model
BUGGY_DIR = 'buggy'
RESULTS_DIR = 'tool_results/deepseek/analyzed_buggy_contracts'
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

PROMPT_TEMPLATE = """
You are an expert smart contract security auditor with deep reasoning capabilities.

TASK: Perform a systematic, step-by-step analysis to find EVERY instance of $bug_type vulnerabilities in this Solidity contract.

REASONING APPROACH:
1. First, understand what constitutes a $bug_type vulnerability
2. Then, scan through the code line-by-line with reasoning
3. For each potential issue, reason through: "Is this truly vulnerable? Why or why not?"
4. Finally, report ALL confirmed vulnerabilities with high confidence

CRITICAL REQUIREMENTS:
- Find EVERY SINGLE occurrence (do not skip similar patterns)
- Use step-by-step reasoning to validate each finding
- Be thorough but precise - balance recall and precision
- Output ONLY valid JSON with exact markers

OUTPUT FORMAT (STRICT):
<<JSON_START>>
{
    "findings": [
        {
            "bug_type": "$bug_type",
            "line_number": 42,
            "code_snippet": "<exact code from that line>",
            "confidence": "high|medium|low",
            "reasoning": "<brief explanation why this is vulnerable>"
        }
    ]
}
<<JSON_END>>

If no vulnerabilities found: <<JSON_START>>{"findings": []}<<JSON_END>>

CONTRACT TO ANALYZE:
$code

REMINDER: Think step-by-step. Find EVERY occurrence. Output ONLY the JSON with markers.
"""

# DEEPSEEK-OPTIMIZED: Reasoning-focused multi-pass prompts
FOCUSED_PROMPTS = {
    'Re-entrancy': [
        {
            'description': 'Identify external calls with reasoning',
            'prompt': """REASONING TASK: Find Re-entrancy vulnerabilities through logical analysis.

Step 1: Identify ALL lines with external calls (.call, .send, .transfer, .delegatecall)
Step 2: For each call, check if state variables are modified AFTER the call
Step 3: Reason: "Does this allow re-entering before state update? If yes, it's vulnerable."

SCAN for these patterns (find EVERY occurrence):
- msg.sender.call(...)
- address.call(...)
- .send(amount)
- .transfer(amount)  
- .delegatecall(...)

For each finding, reason through the vulnerability chain:
1. External call identified → 2. State update after? → 3. Re-entrancy possible?

Output: <<JSON_START>>{{"findings": [{{"bug_type": "Re-entrancy", "line_number": X, "code_snippet": "...", "confidence": "high", "reasoning": "..."}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'tx.origin': [
        {
            'description': 'Find tx.origin with reasoning',
            'prompt': """REASONING TASK: Identify improper tx.origin authentication.

Step 1: Find EVERY line containing 'tx.origin'
Step 2: Reason: "Is this used for authentication/authorization? If yes, it's vulnerable."
Step 3: Explain why tx.origin enables phishing attacks

CRITICAL: Scan ENTIRE contract. tx.origin is ALWAYS a vulnerability when used for auth.

Pattern to find (case-sensitive): 
- tx.origin == 
- tx.origin != 
- require(tx.origin
- if (tx.origin

Output: <<JSON_START>>{{"findings": [{{"bug_type": "tx.origin", "line_number": X, "code_snippet": "...", "confidence": "high", "reasoning": "tx.origin used for authentication enables phishing"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Timestamp-Dependency': [
        {
            'description': 'Find timestamp dependencies with reasoning',
            'prompt': """REASONING TASK: Identify timestamp manipulation vulnerabilities.

Step 1: Find ALL occurrences of timestamp-related keywords:
   - block.timestamp
   - now (deprecated but still used)
   - block.number (when used for time)

Step 2: Reason: "Is this used in critical logic (require, if, math)? Can miner manipulate outcome?"

Step 3: Determine confidence:
   - HIGH: timestamp in require/if affecting money/access
   - MEDIUM: timestamp in calculations
   - LOW: timestamp only for logging

SCAN EVERY LINE for these exact patterns:
- block.timestamp
- now
- block.number (in time context)

Output: <<JSON_START>>{{"findings": [{{"bug_type": "Timestamp-Dependency", "line_number": X, "code_snippet": "...", "confidence": "high/medium", "reasoning": "..."}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Unchecked-Send': [
        {
            'description': 'Find unchecked send/call with reasoning',
            'prompt': """REASONING TASK: Identify unchecked return values from send/call.

Step 1: Find ALL .send() and low-level .call{value:...} operations
Step 2: Reason: "Is the return value checked? If not, failures go unnoticed = vulnerable"

Patterns indicating vulnerability:
- address.send(...);  [semicolon immediately = unchecked]
- .call{value:...}(...);  [not assigned to variable = unchecked]

Safe patterns (NOT vulnerable):
- require(address.send(...));  [checked with require]
- bool success = address.send(...); require(success);  [checked]

Output: <<JSON_START>>{{"findings": [{{"bug_type": "Unchecked-Send", "line_number": X, "code_snippet": "...", "confidence": "high", "reasoning": "return value not checked"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Unhandled-Exceptions': [
        {
            'description': 'Find unhandled exceptions with reasoning',
            'prompt': """REASONING TASK: Identify unhandled exceptions from external calls.

Step 1: Find ALL external calls that can throw exceptions:
   - .call()
   - .delegatecall()
   - address.send()
   - External contract calls

Step 2: Reason: "Is there try-catch or return value check? If no, exception unhandled = vulnerable"

Vulnerable patterns:
- someContract.someFunction();  [no try-catch, no return check]
- address.call(...);  [not wrapped in require or try-catch]

Safe patterns:
- try someContract.someFunction() { } catch { }
- require(address.call(...))

Output: <<JSON_START>>{{"findings": [{{"bug_type": "Unhandled-Exceptions", "line_number": X, "code_snippet": "...", "confidence": "medium/high", "reasoning": "..."}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'TOD': [
        {
            'description': 'Find TOD (Transaction Order Dependence) with reasoning',
            'prompt': """REASONING TASK: Identify Transaction Order Dependence (front-running) vulnerabilities.

Step 1: Find state-dependent operations that can be front-run:
   - Checking balance before transfer
   - Checking condition before action
   - Race conditions in state updates

Step 2: Reason: "Can attacker observe this transaction and front-run it by changing state?"

Vulnerable patterns:
- if (balance > X) { transfer } // attacker can drain between check and transfer
- require(someState == value); doSomething(); // state can change between transactions

Keywords to look for:
- balance checks followed by transfers
- state checks in multi-step operations
- approval + transferFrom patterns

Output: <<JSON_START>>{{"findings": [{{"bug_type": "TOD", "line_number": X, "code_snippet": "...", "confidence": "medium", "reasoning": "state check vulnerable to front-running"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Overflow-Underflow': [
        {
            'description': 'Find integer overflow/underflow with reasoning',
            'prompt': """REASONING TASK: Identify integer overflow/underflow vulnerabilities.

Step 1: Find ALL arithmetic operations on uint/int variables:
   - Addition: +
   - Subtraction: -
   - Multiplication: *
   - Division: /

Step 2: Reason: "Is this Solidity <0.8.0? If yes, no automatic overflow check = vulnerable"
          "For Solidity >=0.8.0: Is 'unchecked' block used? If yes, vulnerable"

Step 3: Check for SafeMath usage (if present, NOT vulnerable)

Vulnerable patterns (Solidity <0.8.0 without SafeMath):
- balance + amount
- value - deduction
- price * quantity

Check pragma version first!

Output: <<JSON_START>>{{"findings": [{{"bug_type": "Overflow-Underflow", "line_number": X, "code_snippet": "...", "confidence": "high/medium", "reasoning": "arithmetic without overflow protection"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ]
}

# Bug types to analyze (7 types total)
BUG_TYPES = [
    'Re-entrancy',
    'Timestamp-Dependency', 
    'Unchecked-Send',
    'Unhandled-Exceptions',
    'TOD',
    'tx.origin',
    'Overflow-Underflow'
]

def call_ollama_api(prompt, retries=MAX_RETRIES):
    """Call Ollama API with retry logic for DeepSeek-R1"""
    for attempt in range(retries):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    'model': MODEL,
                    'prompt': prompt,
                    'stream': False,
                    'options': {
                        'temperature': 0.1,  # Lower temperature for more consistent reasoning
                        'top_p': 0.9,
                        'num_ctx': 8192  # Larger context for reasoning chains
                    }
                },
                timeout=300  # 5 min timeout for reasoning models
            )
            response.raise_for_status()
            return response.json().get('response', '')
        except RequestException as e:
            if attempt < retries - 1:
                print(f"  ⚠ API call failed (attempt {attempt + 1}/{retries}): {e}")
                time.sleep(RETRY_DELAY)
            else:
                print(f"  ✗ API call failed after {retries} attempts: {e}")
                return None
    return None

def multi_pass_analysis(code, bug_type):
    all_findings = []
    
    if bug_type in FOCUSED_PROMPTS:
        focused_prompts = FOCUSED_PROMPTS[bug_type]
        print(f"  → Running {len(focused_prompts)} reasoning passes for {bug_type}")
        
        for i, prompt_config in enumerate(focused_prompts, 1):
            print(f"    Pass {i}/{len(focused_prompts)}: {prompt_config['description']}")
            prompt = Template(prompt_config['prompt']).substitute(code=code, bug_type=bug_type)
            
            response = call_ollama_api(prompt)
            if response:
                findings = extract_json_from_text(response)
                if findings and 'findings' in findings:
                    all_findings.extend(findings['findings'])
                    print(f"      Found: {len(findings['findings'])} instances")
    
    # Deduplicate by line number
    unique_findings = {}
    for finding in all_findings:
        line = finding.get('line_number')
        if line and line not in unique_findings:
            unique_findings[line] = finding
    
    return list(unique_findings.values())

def analyze_contract(contract_path, bug_type):
    """
    Analyze a single contract for a specific bug type using DeepSeek-R1
    """
    with open(contract_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    contract_name = extract_contract_name(contract_path)
    print(f"\n📄 Analyzing {contract_name} for {bug_type}...")
    
    # Use multi-pass reasoning analysis
    findings = multi_pass_analysis(code, bug_type)
    
    if not findings:
        # Fallback: use main reasoning prompt if focused prompts found nothing
        print(f"  → No findings in focused passes, trying main reasoning prompt...")
        prompt = Template(PROMPT_TEMPLATE).substitute(code=code, bug_type=bug_type)
        response = call_ollama_api(prompt)
        
        if response:
            parsed = extract_json_from_text(response)
            if parsed and 'findings' in parsed:
                findings = parsed['findings']
    
    print(f"  ✓ Total findings: {len(findings)}")
    return findings

def save_results(contract_path, bug_type, findings):
    """Save analysis results to JSON file"""
    contract_name = os.path.basename(contract_path)
    bug_dir = os.path.join(RESULTS_DIR, bug_type, 'results')
    os.makedirs(bug_dir, exist_ok=True)
    
    output_file = os.path.join(bug_dir, f"{contract_name}.json")
    
    result = {
        'contract': contract_name,
        'bug_type': bug_type,
        'model': MODEL,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'findings': findings
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    
    return output_file

def main():
    """
    Main evaluation loop for DeepSeek-R1
    Analyzes all buggy contracts across all bug types
    """
    print(f"""
    Model: {MODEL}
    Bug Types: {len(BUG_TYPES)}
    Expected Performance: F1~0.15-0.20, Recall~10-15%
    Target: Beat Manticore (F1=0.1491), rank 5th/8

    Starting evaluation...
""")
    
    start_time = time.time()
    total_contracts = 0
    total_findings = 0
    
    for bug_type in BUG_TYPES:
        print(f"\n{'='*70}")
        print(f"🔍 BUG TYPE: {bug_type}")
        print(f"{'='*70}")
        
        bug_dir = os.path.join(BUGGY_DIR, bug_type)
        if not os.path.exists(bug_dir):
            print(f"  ⚠ Directory not found: {bug_dir}")
            continue
        
        contracts = [f for f in os.listdir(bug_dir) if f.endswith('.sol')]
        print(f"Found {len(contracts)} contracts")
        
        for i, contract_file in enumerate(sorted(contracts), 1):
            contract_path = os.path.join(bug_dir, contract_file)
            print(f"\n[{i}/{len(contracts)}] {contract_file}")
            
            findings = analyze_contract(contract_path, bug_type)
            save_results(contract_path, bug_type, findings)
            
            total_contracts += 1
            total_findings += len(findings)
    
    elapsed = time.time() - start_time
    
    print(f"""
Total Contracts Analyzed: {total_contracts}
Total Findings: {total_findings}
Time Elapsed: {elapsed/60:.1f} minutes
Average: {elapsed/total_contracts:.1f} seconds per contract

Results saved to: {RESULTS_DIR}

Next step: Run comparison with ground truth
  python3 compare_with_ground_truth.py --results-dir tool_results/deepseek
""")

if __name__ == '__main__':
    main()
