#!/usr/bin/env python3
"""Helper functions for LLM evaluation and comparison with static analysis tools"""

import re
import json
from typing import Tuple, List, Optional

try:
    import demjson3 as _demjson
except Exception:
    _demjson = None


def extract_contract_name(code: str) -> Optional[str]:
    """Extract the first contract name found in Solidity source code"""
    m = re.search(r'\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)', code)
    if m:
        return m.group(1)
    return None


def coerce_line_number(value) -> Optional[int]:
    """Coerce common numeric types/strings to int; return None if invalid or <=0"""
    if value is None:
        return None
    try:
        if isinstance(value, str):
            v = value.strip()
            if not v:
                return None
            v = int(float(v))  # handle "42.0"
        else:
            v = int(value)
        if v <= 0:
            return None
        return v
    except Exception:
        return None


def map_llm_to_subtypes(llm_bug_type: str) -> str:
    """Map broad LLM bug types to one representative static-tool sub-type."""
    mapping = {
        "Re-entrancy": "DAO",
        "Timestamp-Dependency": "Timestamp-Dependency",
        "Unchecked-Send": "Unchecked-Send",
        "Unhandled-Exceptions": "Unhandled-Exceptions",
        "TOD": "TOD",
        "Overflow-Underflow": "Overflow-Underflow",
        "tx.origin": "tx.origin"
    }
    return mapping.get(llm_bug_type, llm_bug_type)


def map_llm_to_severity(llm_bug_type: str) -> str:
    """Map LLM bug type to default severity (Violation or Warning)"""
    severity_map = {
        "Re-entrancy": "Violation",
        "Unchecked-Send": "Violation",
        "Unhandled-Exceptions": "Warning",
        "Timestamp-Dependency": "Warning",
        "TOD": "Warning",
        "Overflow-Underflow": "Warning",
        "tx.origin": "Warning"
    }
    return severity_map.get(llm_bug_type, "Warning")


def extract_context_from_code(code: str, line_number: int, before: int = 2, after: int = 2) -> Tuple[List[str], List[str]]:
    """Return context_before and context_after lists (strings). line_number is 1-based."""
    lines = code.splitlines()
    idx = max(0, line_number - 1)
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    ctx_before = [l.rstrip() for l in lines[start:idx]]
    ctx_after = [l.rstrip() for l in lines[idx + 1:end]]
    return ctx_before, ctx_after


def extract_json_from_text(text: str) -> dict:
    """Try to extract a JSON object from LLM text output robustly.
    
    Strategies (in order):
    1. Look for explicit markers <<JSON_START>> / <<JSON_END>> and parse inside
    2. Find the first balanced '{' ... '}' substring and attempt to parse that
    3. Try tolerant JSON parsing with demjson3 if available
    
    Returns parsed dict or empty dict on failure.
    """
    if not text or not isinstance(text, str):
        return {}
    
    # If text looks like NDJSON (many small JSON objects per line with a 'response' field), 
    # assemble the 'response' fragments first
    assembled = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Try to detect the NDJSON response objects that include a 'response' field
        try:
            if line.startswith('{'):
                obj = json.loads(line)
                if isinstance(obj, dict) and 'response' in obj and isinstance(obj['response'], str):
                    assembled.append(obj['response'])
                    continue
        except Exception:
            # ignore parse errors here and fall back to other strategies
            pass
        # Some streaming outputs emit lines like: {"model":"...","response":"text..."}
        # If we didn't parse it as JSON, try a quick heuristic to extract a "response":"..." substring
        if '"response"' in line:
            try:
                # naive extraction between "response": and the last quote
                idx = line.find('"response"')
                colon = line.find(':', idx)
                if colon != -1:
                    frag = line[colon + 1:].strip().lstrip()
                    # remove leading/ending commas
                    frag = frag.rstrip(',')
                    # if it's a quoted string, strip outer quotes
                    if frag.startswith('"') and frag.endswith('"') and len(frag) >= 2:
                        frag = frag[1:-1]
                    assembled.append(frag)
            except Exception:
                pass
    
    if assembled:
        text = ''.join(assembled)
    
    # Normalize common escaped unicode markers (some streams encode '<' as '\u003c')
    if '\\u003c' in text or '\\u003e' in text:
        try:
            text = text.encode('utf-8').decode('unicode_escape')
        except Exception:
            text = text.replace('\\u003c', '<').replace('\\u003e', '>')
    
    # 1. Direct JSON parse attempt
    try:
        return json.loads(text)
    except Exception:
        pass
    
    # 2. Marker-based extraction (accept both literal <<JSON_START>> and variants)
    m = re.search(r'<<JSON_START>>(.*?)<<JSON_END>>', text, re.S)
    if m:
        candidate = m.group(1).strip()
        try:
            return json.loads(candidate)
        except Exception:
            if _demjson:
                try:
                    return _demjson.decode(candidate)
                except Exception:
                    pass
    
    # If markers are present but encoded differently, try to find 'JSON_START' and then first '{'
    if 'JSON_START' in text and 'JSON_END' in text:
        idx = text.find('JSON_START')
        brace_idx = text.find('{', idx)
        end_brace_idx = text.rfind('JSON_END')
        if brace_idx != -1 and end_brace_idx != -1 and end_brace_idx > brace_idx:
            candidate = text[brace_idx:text.rfind('}', idx, end_brace_idx) + 1]
            try:
                return json.loads(candidate)
            except Exception:
                if _demjson:
                    try:
                        return _demjson.decode(candidate)
                    except Exception:
                        pass
    
    # 3. Best-effort balanced-brace extraction: find first '{' and grab until matching '}'
    start = text.find('{')
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        return json.loads(candidate)
                    except Exception:
                        # try tolerant parser then give up
                        if _demjson:
                            try:
                                return _demjson.decode(candidate)
                            except Exception:
                                break
                        break
    
    # 4. Last resort: try demjson3 on the whole text
    if _demjson:
        try:
            return _demjson.decode(text)
        except Exception:
            pass
    
    return {}
