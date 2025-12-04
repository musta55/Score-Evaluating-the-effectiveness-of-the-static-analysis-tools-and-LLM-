# Score - Evaluating the Effectiveness of the Static Analysis tools and LLMs

This repository contains the SolidiFI benchmark for evaluating static analysis tools and Large Language Models (LLMs) on Solidity smart contracts.

## Prerequisites

*   **Python 3.8+**
*   **Solidity Compiler (`solc`)**: Required for generating ASTs during bug injection.
    *   macOS: `brew install solidity`
    *   Ubuntu: `sudo apt-get install solc`
    *   npm: `npm install -g solc`
*   **Ollama**: Required for running local LLM evaluations.
    *   Download: [https://ollama.com/](https://ollama.com/)

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd Score-Evaluating-the-effectiveness-of-the-static-analysis-tools-and-LLM-
    ```

2.  Install Python dependencies:
    ```bash
    cd Score
    pip install -r requirements.txt
    ```

## Running the Experiment

### 1. Bug Injection (Dataset Generation)

To generate the dataset of buggy contracts by injecting vulnerabilities into clean contracts:

**Option A: Inject bugs into ALL contracts (Recommended)**
```bash
cd Score
python3 injection/inject_all.py
```
*   This will create a `buggy/` directory containing contracts with injected vulnerabilities (e.g., Re-entrancy, Overflow-Underflow).

**Option B: Inject bugs into a SINGLE contract**
```bash
cd Score
python3 injection/solidifi.py -i contracts/1.sol Re-entrancy
```
*   Supported bug types: `Re-entrancy`, `Timestamp-Dependency`, `Unchecked-Send`, `Unhandled-Exceptions`, `TOD`, `Overflow-Underflow`, `tx.origin`.
*   **Note:** Ensure `solc` is in your system PATH.

### 2. LLM Evaluation (Local)

To evaluate the buggy contracts using a local LLM (e.g., Llama 3 or DeepSeek) via Ollama:

1.  **Start Ollama Server:**
    Open a terminal and run:
    ```bash
    ollama serve
    ```

2.  **Pull the Model:**
    In a separate terminal, pull the required model:
    *   For Llama 3:
        ```bash
        ollama pull llama3
        ```
    *   For DeepSeek R1:
        ```bash
        ollama pull deepseek-r1:7b
        ```

3.  **Run the Evaluator:**
    *   **Llama 3:**
        ```bash
        cd Score
        python3 evaluation/llm_evaluator_llama3.py
        ```
        Results saved to: `tool_results/LLM/analyzed_buggy_contracts`

    *   **DeepSeek R1:**
        ```bash
        cd Score
        python3 evaluation/llm_evaluator_deepseek.py
        ```
        Results saved to: `tool_results/deepseek/analyzed_buggy_contracts`

### 3. Analysis

Analysis scripts are located in `Score/Benchmark analysis/`. You can use them to compare results against ground truth and generate metrics.

**Step 1: Generate Ground Truth**
First, merge the injection logs to create a ground truth CSV file:
```bash
cd Score/Benchmark analysis
python3 merge_bug_logs.py
```
*   This creates `merged_bug_logs.csv`.

**Step 2: Compare Results**
Compare the LLM findings against the ground truth:
```bash
python3 compare_with_ground_truth.py --ground-truth merged_bug_logs.csv
```
*   This will output precision, recall, and F1-scores.
*   Use `--llm-dir` to specify a different results directory (default: `../tool_results/LLM/analyzed_buggy_contracts`).

## Project Structure

*   `Score/`: Main source code.
    *   `injection/`: Scripts for bug injection (`solidifi.py`, `inject_all.py`).
    *   `evaluation/`: Scripts for LLM evaluation (`llm_evaluator_llama3.py`, `llm_evaluator_deepseek.py`).
    *   `configs/`: Configuration files for bug types and injection patterns.
    *   `buggy/`: Generated buggy contracts.
    *   `tool_results/`: Output directory for analysis tools.
*   `Score/Benchmark analysis/`: Scripts for calculating precision, recall, and F1-scores.
