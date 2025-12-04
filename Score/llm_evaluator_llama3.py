import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'Benchmark analysis'))
from evaluation_helpers import (
    extract_contract_name,
    coerce_line_number,
    map_llm_to_subtypes,
    map_llm_to_severity,
    extract_context_from_code,
    extract_json_from_text
)

import json
from string import Template
import time
import requests
from requests.exceptions import RequestException

# Configuration
OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL = 'llama3:latest'  # Change to 'llama3:70b-instruct' for larger model
BUGGY_DIR = 'buggy'
RESULTS_DIR = 'tool_results/LLM/analyzed_buggy_contracts'
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# IMPROVEMENT 1: EXHAUSTIVE PROMPT
PROMPT_TEMPLATE = """
CRITICAL INSTRUCTION
You MUST find EVERY SINGLE occurrence of $bug_type vulnerabilities in this contract.
Do NOT skip similar patterns. Do NOT summarize. Report ALL instances separately.
Even if patterns appear repetitive, list EACH occurrence with its specific line number.

IMPORTANT: Output MUST be valid JSON only. Do not include any explanatory text. The only permitted extra tokens are the exact markers <<JSON_START>> and <<JSON_END>> surrounding the JSON object.

Surround the JSON response with the markers <<JSON_START>> and <<JSON_END>> and output NOTHING else outside those markers.

Analyze the following Solidity smart contract for EVERY instance of: $bug_type

Scan EVERY line carefully. Return ALL findings in this exact JSON format:
<<JSON_START>>
{
    "findings": [
        {
            "bug_type": "$bug_type",
            "line_number": 42,
            "code_snippet": "<relevant code snippet>",
            "confidence": "high|medium|low"
        }
    ]
}
<<JSON_END>>

If no vulnerabilities of type $bug_type are found, return exactly: <<JSON_START>>{"findings": []}<<JSON_END>>

CONTRACT TO ANALYZE:
$code
"""

# IMPROVEMENT 2: MULTI-PASS FOCUSED PROMPTS
FOCUSED_PROMPTS = {
    'Re-entrancy': [
        {
            'description': 'External calls before state updates',
            'prompt': """Find EVERY line where external calls (.call, .send, .transfer, .delegatecall) are made.
List ALL occurrences with line numbers. Look for:
- msg.sender.call
- address.call
- .send(
- .transfer(
- .delegatecall

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Re-entrancy", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        },
        {
            'description': 'State updates after calls',
            'prompt': """Find EVERY pattern where state variables are modified AFTER external calls.
Look for assignment statements (=) that come after .call/.send/.transfer on previous lines.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Re-entrancy", "line_number": X, "code_snippet": "...", "confidence": "medium"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'tx.origin': [
        {
            'description': 'tx.origin usage',
            'prompt': """Find EVERY single line containing 'tx.origin'.
Scan the entire contract and list ALL occurrences with exact line numbers.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "tx.origin", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Timestamp-Dependency': [
        {
            'description': 'Timestamp usage',
            'prompt': """Find EVERY line containing: block.timestamp, now, block.number
List ALL occurrences separately with line numbers.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Timestamp-Dependency", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        },
        {
            'description': 'Time-based conditions',
            'prompt': """Find EVERY conditional statement (if, require, assert) that uses time-based comparisons.
Look for comparisons involving timestamps, block numbers, or time units (days, hours, etc.).

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Timestamp-Dependency", "line_number": X, "code_snippet": "...", "confidence": "medium"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Unchecked-Send': [
        {
            'description': 'Unchecked send/transfer',
            'prompt': """Find EVERY .send( or .transfer( call that is NOT checked with require, assert, or if statement.
List ALL occurrences with line numbers.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Unchecked-Send", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Unhandled-Exceptions': [
        {
            'description': 'Low-level calls without checks',
            'prompt': """Find EVERY low-level call (.call, .callcode, .delegatecall) where the return value is NOT checked.
Look for calls without: require(success), if (success), assert(success)

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Unhandled-Exceptions", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'TOD': [
        {
            'description': 'State-dependent external calls',
            'prompt': """Find EVERY external call whose behavior depends on contract state that could be modified by another transaction.
Look for: calls that depend on balances, mappings, or state variables.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "TOD", "line_number": X, "code_snippet": "...", "confidence": "medium"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ],
    'Overflow-Underflow': [
        {
            'description': 'Arithmetic operations',
            'prompt': """Find EVERY arithmetic operation (+, -, *, /) on uint or int types WITHOUT SafeMath.
List ALL occurrences with line numbers.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Overflow-Underflow", "line_number": X, "code_snippet": "...", "confidence": "high"}}]}}<<JSON_END>>

Contract:
$code"""
        },
        {
            'description': 'Unchecked increments',
            'prompt': """Find EVERY ++ or -- operation, and += or -= operations.
List ALL occurrences that are not protected by SafeMath.

Return JSON: <<JSON_START>>{{"findings": [{{"bug_type": "Overflow-Underflow", "line_number": X, "code_snippet": "...", "confidence": "medium"}}]}}<<JSON_END>>

Contract:
$code"""
        }
    ]
}

# Example prompt (unchanged)
EXAMPLE_PROMPT_SNIPPET = """
Example 1 (Timestamp-Dependency):
pragma solidity ^0.5.0;
contract ExampleTimestamp {
    function isOld(uint startTime) public view returns (bool) {
        return startTime + 1 days == block.timestamp;
    }
}

Example output:
<<JSON_START>>
{
    "findings": [
        {
            "bug_type": "Timestamp-Dependency",
            "line_number": 3,
            "code_snippet": "return startTime + 1 days == block.timestamp;",
            "confidence": "high"
        }
    ]
}
<<JSON_END>>

Example 2 (Re-entrancy):
pragma solidity ^0.5.0;
contract ExampleReentrancy {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call.value(amount)("");
        require(success);
        balances[msg.sender] = 0;
    }
}

Example output:
<<JSON_START>>
{
    "findings": [
        {
            "bug_type": "Re-entrancy",
            "line_number": 6,
            "code_snippet": "(bool success, ) = msg.sender.call.value(amount)(\"\");",
            "confidence": "high"
        }
    ]
}
<<JSON_END>>
"""

BUG_TYPES = [
    'Re-entrancy',
    'Timestamp-Dependency',
    'Unchecked-Send',
    'Unhandled-Exceptions',
    'TOD',
    'Overflow-Underflow',
    'tx.origin'
]


def check_ollama_available():
    """Check if Ollama server is running and accessible by listing models"""
    try:
        response = requests.get('http://localhost:11434/api/tags')
        response.raise_for_status()

        models = response.json().get('models', [])
        if not any(m.get('name') == MODEL for m in models):
            print(f"\nWarning: Model '{MODEL}' not found. Available models:")
            for m in models:
                print(f"  - {m.get('name')}")
            print(f"\nPlease pull the model with: ollama pull {MODEL}")
            return False
        return True
    except requests.exceptions.ConnectionError:
        print("\nError: Cannot connect to Ollama server.")
        print("Please ensure Ollama is running: ollama serve")
        return False
    except Exception as e:
        print(f"\nError checking Ollama: {str(e)}")
        return False


def query_ollama(prompt, model=MODEL, retries=MAX_RETRIES):
    """Query Ollama with retry logic (non-streaming). Returns the full text response."""
    last_error = None
    for attempt in range(retries):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    'model': model,
                    'prompt': prompt,
                    'temperature': 0,
                    'max_tokens': 1200  # Increased for more findings
                },
                timeout=180,  # Increased timeout for larger models
                stream=False
            )
            response.raise_for_status()
            text_full = response.text
            if text_full and isinstance(text_full, str):
                return text_full.strip()
            else:
                raise RuntimeError("Empty response from Ollama")
        except RequestException as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
    raise RuntimeError(f"Failed to query Ollama after {retries} attempts: {last_error}")


def multi_pass_analysis(code, bug_type, contract_filename):
    """
    IMPROVEMENT 2: Multi-pass analysis with focused prompts
    Returns aggregated findings from multiple focused queries
    """
    all_findings = []
    
    # Get focused prompts for this bug type
    focused_prompts_list = FOCUSED_PROMPTS.get(bug_type, [])
    
    if not focused_prompts_list:
        # Fallback to single general prompt if no focused prompts defined
        print(f"    ⚠️  No focused prompts for {bug_type}, using general prompt")
        prompt = EXAMPLE_PROMPT_SNIPPET + "\n\n" + Template(PROMPT_TEMPLATE).safe_substitute(
            code=code, bug_type=bug_type
        )
        llm_response = query_ollama(prompt)
        parsed = extract_json_from_text(llm_response)
        if parsed and isinstance(parsed, dict):
            findings = parsed.get('findings', [])
            all_findings.extend(findings)
    else:
        # Run multiple focused passes
        print(f"    🔍 Running {len(focused_prompts_list)} focused passes...")
        for idx, focused_prompt_info in enumerate(focused_prompts_list, 1):
            try:
                description = focused_prompt_info['description']
                prompt_template = focused_prompt_info['prompt']
                
                print(f"       Pass {idx}/{len(focused_prompts_list)}: {description}")
                
                prompt = EXAMPLE_PROMPT_SNIPPET + "\n\n" + Template(prompt_template).safe_substitute(
                    code=code, bug_type=bug_type
                )
                llm_response = query_ollama(prompt)
                parsed = extract_json_from_text(llm_response)
                
                if parsed and isinstance(parsed, dict):
                    findings = parsed.get('findings', [])
                    all_findings.extend(findings)
                    print(f"       ✓ Found {len(findings)} instances")
                else:
                    print(f"       ✗ No valid JSON response")
                    
                # Small delay between passes to avoid overwhelming the model
                time.sleep(0.5)
                
            except Exception as e:
                print(f"       ✗ Error in pass {idx}: {str(e)}")
                continue
    
    # Deduplicate findings by line number (keep highest confidence)
    deduplicated = {}
    for finding in all_findings:
        if not isinstance(finding, dict):
            continue
        
        line_num = coerce_line_number(finding.get('line_number'))
        if not line_num or line_num <= 0:
            continue
        
        # If we already have this line, keep the one with higher confidence
        if line_num in deduplicated:
            existing_conf = deduplicated[line_num].get('confidence', 'low')
            new_conf = finding.get('confidence', 'low')
            conf_order = {'high': 3, 'medium': 2, 'low': 1}
            if conf_order.get(new_conf, 0) > conf_order.get(existing_conf, 0):
                deduplicated[line_num] = finding
        else:
            deduplicated[line_num] = finding
    
    final_findings = list(deduplicated.values())
    print(f"    📊 Total findings after deduplication: {len(final_findings)}")
    return final_findings


def evaluate_contracts():
    """Evaluate all buggy contracts using the IMPROVED LLM approach"""
    if not os.path.exists(BUGGY_DIR) or not os.listdir(BUGGY_DIR):
        print(f"\nError: {BUGGY_DIR}/ directory is empty or doesn't exist.")
        print("Please run the bug injection first:\n  python3 inject_all.py")
        return

    print(f"\n{'='*80}")
    print(f"🚀 LLM EVALUATOR - IMPROVED VERSION")
    print(f"{'='*80}")
    print(f"\n📋 Improvements Applied:")
    print(f"   1. ✅ Exhaustive Detection Prompts")
    print(f"   2. ✅ Multi-Pass Focused Analysis")
    print(f"   3. ✅ Model: {MODEL}")
    print(f"\n{'='*80}\n")

    print(f"Checking Ollama availability...")
    try:
        if not check_ollama_available():
            print("\nError: Ollama server not running. Please start it with:")
            print("  ollama serve")
            return
        print("✓ Ollama server is ready.\n")
    except Exception as e:
        print(f"\nError checking Ollama: {e}")
        return

    for bug_type in os.listdir(BUGGY_DIR):
        bug_type_dir = os.path.join(BUGGY_DIR, bug_type)
        if not os.path.isdir(bug_type_dir):
            continue

        print(f"\n{'─'*80}")
        print(f"📂 Processing bug type: {bug_type}")
        print(f"{'─'*80}")
        
        result_type_dir = os.path.join(RESULTS_DIR, bug_type, 'results')
        os.makedirs(result_type_dir, exist_ok=True)

        contracts = [f for f in os.listdir(bug_type_dir) if f.endswith('.sol')]
        if not contracts:
            print(f"No .sol files found in {bug_type_dir}")
            continue
            
        # Support SINGLE_CONTRACT env var for testing
        single = os.environ.get('SINGLE_CONTRACT')
        if single:
            parts = single.split('/', 1)
            if len(parts) == 2 and parts[0] == bug_type:
                target = parts[1]
                if target in contracts:
                    contracts = [target]
                else:
                    print(f"Requested SINGLE_CONTRACT {single} not found")
                    contracts = []
            else:
                contracts = []
        if not contracts:
            continue

        for i, filename in enumerate(contracts, 1):
            contract_path = os.path.join(bug_type_dir, filename)
            print(f"\n  [{i}/{len(contracts)}] 📄 {filename}")

            try:
                with open(contract_path, 'r') as f:
                    code = f.read()
                
                contract_name = extract_contract_name(code) or filename.replace('.sol', '')
                
                # IMPROVEMENT 2: Use multi-pass analysis
                findings = multi_pass_analysis(code, bug_type, filename)
                
                # Enrich findings with context, sub_type, severity
                enriched_findings = []
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    
                    line_num = coerce_line_number(finding.get('line_number'))
                    if line_num is None or line_num <= 0:
                        continue
                    
                    code_snippet = finding.get('code_snippet', '').strip()
                    confidence = finding.get('confidence', 'low')
                    
                    sub_type = map_llm_to_subtypes(bug_type)
                    severity = map_llm_to_severity(bug_type)
                    
                    try:
                        ctx_before, ctx_after = extract_context_from_code(code, line_num, before=2, after=2)
                    except Exception:
                        ctx_before, ctx_after = [], []
                    
                    enriched_findings.append({
                        "bug_type": bug_type,
                        "sub_type": sub_type,
                        "severity": severity,
                        "line_number": line_num,
                        "code_snippet": code_snippet,
                        "confidence": confidence,
                        "context_before": ctx_before,
                        "context_after": ctx_after
                    })
                
                result = {
                    'contract': filename,
                    'contract_name': contract_name,
                    'bug_type': bug_type,
                    'findings': enriched_findings,
                    'success': bool(enriched_findings),
                    'improved_version': True,
                    'multi_pass_enabled': bool(FOCUSED_PROMPTS.get(bug_type))
                }
                
                result_filename = filename.replace('.sol', '.sol.json')
                result_path = os.path.join(result_type_dir, result_filename)
                with open(result_path, 'w') as out:
                    json.dump(result, out, indent=2)
                
                status = "✓" if enriched_findings else "✗"
                print(f"  {status} Results saved: {len(enriched_findings)} findings")
                
            except Exception as e:
                print(f"  ✗ Error: {str(e)}")
                continue

    print(f"\n{'='*80}")
    print(f"✅ IMPROVED EVALUATION COMPLETE")
    print(f"{'='*80}\n")


if __name__ == '__main__':
    evaluate_contracts()
