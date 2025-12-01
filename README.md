# Score Project (Static + LLM Evaluators)

This repository contains a framework for evaluating smart contracts' static analysis tools via **bug injection**, with additional support for **LLM-based vulnerability detection**.

## Overview

This framework evaluates smart contract analysis tools by:

- **Injecting bugs** of different types into a dataset of real-world smart contracts.
- **Running static analysis tools** on the injected (buggy) contracts.
- **Inspecting the tools' reports** to measure false negatives, false positives, and misclassified bugs.

## Repository Layout

- `Score/` – Core bug-injection and evaluation framework plus extensions:
  - `contracts/`: Original smart contracts dataset.
  - `bugs/`: Bug snippets used for injection.
  - `bug_types.conf`, `code_trans.conf`, `sec_methods.conf`: Configuration for bug types, transformations, and security methods.
  - `solidifi.py`, `inject_file.py`, `inject_all.py`: Bug injection utilities.
  - `evaluator.py`, `evaluation_helpers.py`, `merge_bug_logs.py`, `compare_with_ground_truth.py`: Evaluation and metrics utilities.
  - `tool_results/`: Outputs of static analyzers and LLM-based tools.
    - Per-tool subfolders (e.g., `Mythril`, `Slither`, `Manticore`, `Smartcheck`, `Securify`, `Oyente`).
    - LLM results under `tool_results/llama3_improved/` and `tool_results/deepseek/`.
- `Score- Benchmark/` – Benchmark and aggregated artifacts:
  - `results/`: Per-tool evaluation outputs on the benchmark.
  - `FNs/`, `FPs/`: False negative / false positive breakdowns.
  - `tool_results/LLM` and `tool_results/DeepSeek`: LLM evaluation outputs on the benchmark.
  - `scripts/`: Helper scripts for inspecting and reusing the benchmark.

## Quick Start (Static Analysis)

### 1. Install dependencies

From the `Score` directory:

```bash
cd "Score"
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

You also need a Solidity compiler compatible with the contracts and tools used here (for example, `solc` 0.5.x).

### 2. Inject bugs into a contract

To inject bugs of a specific type into a Solidity contract:

```bash
python3 solidifi.py -i contracts/1.sol Timestamp-Dependency
```

The generated buggy contracts and injection logs are stored under `buggy/<Bug-Type>/`.

Valid bug types include:

- `Re-entrancy`
- `Timestamp-Dependency`
- `Unchecked-Send`
- `Unhandled-Exceptions`
- `TOD`
- `Overflow-Underflow`
- `tx.origin`

### 3. Evaluate static analysis tools

To reproduce a full evaluation of the static analyzers from scratch:

```bash
python3 evaluator.py Oyente,Securify,Mythril,Smartcheck,Manticore,Slither
```

This will:

- Inject bugs into the contracts dataset under `contracts/`.
- Run the selected tools on the buggy contracts.
- Analyze tool reports to compute FNs, FPs, and misidentified bugs, storing results under `tool_results/`.

## Using the LLM Evaluators

This project includes **LLM-based evaluators** that treat an LLM as another analysis tool.

- **LLM evaluators (local Ollama API):**
  - `llm_evaluator_llama3.py`: Uses a `llama3`-family model via Ollama.
  - `llm_evaluator_deepseek.py`: Uses `deepseek-r1` via Ollama.
- **Input contracts**: Read from the `buggy/` directory (same injected contracts used for static tools).
- **Outputs**:
  - Raw, per-contract findings under `tool_results/LLM/analyzed_buggy_contracts` or `tool_results/deepseek/analyzed_buggy_contracts`.
  - Aggregated CSVs/JSONs under:
    - `Score/tool_results/llama3_improved/`
    - `Score/tool_results/deepseek/`

### 1. Start Ollama with the required models

Make sure the Ollama server is running and the models are available:

```bash
ollama serve
ollama pull llama3
ollama pull deepseek-r1:7b
```

By default, the scripts expect Ollama at `http://localhost:11434`.

### 2. Run the LLM evaluator with Llama 3

From the `Score` directory:

```bash
python3 llm_evaluator_llama3.py
```

This will:

- Iterate over buggy contracts under `buggy/`.
- Query the `llama3` model for each bug type.
- Write analysis outputs under `tool_results/LLM/analyzed_buggy_contracts` and summary CSVs under `tool_results/llama3_improved/`.

### 3. Run the LLM evaluator with DeepSeek-R1

From the `Score` directory:

```bash
python3 llm_evaluator_deepseek.py
```

This will:

- Iterate over the same buggy contracts.
- Use the `deepseek-r1:7b` model for reasoning-intensive detection.
- Write analysis outputs under `tool_results/deepseek/analyzed_buggy_contracts` and summary CSVs under `tool_results/deepseek/`.

### 4. Compare LLMs with traditional tools

You can compare LLM performance with traditional static analyzers using the existing helpers, for example:

```bash
python3 compare_with_ground_truth.py
python3 generate_metrics_csv.py
```

These scripts use the artifacts in `tool_results/` (both traditional tools and LLMs) to compute precision, recall, F1, and per-bug-type metrics.

The project is organized so that other users can:

- Reuse the **bug injection and evaluation pipeline**.
- Plug in new **LLM models** (by adapting the `MODEL`, `RESULTS_DIR`, and prompts in the LLM evaluator scripts).
- Compare those models directly against classic static analysis tools using the same benchmark.
