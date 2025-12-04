# SolidiFI & LLM Evaluation Benchmark

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

```bash
cd Score
python3 inject_all.py
```
*   This will create a `buggy/` directory containing contracts with injected vulnerabilities (e.g., Re-entrancy, Overflow-Underflow).
*   **Note:** Ensure `solc` is in your system PATH.

### 2. LLM Evaluation (Local)

To evaluate the buggy contracts using a local LLM (e.g., Llama 3) via Ollama:

1.  **Start Ollama Server:**
    Open a terminal and run:
    ```bash
    ollama serve
    ```

2.  **Pull the Model:**
    In a separate terminal, pull the required model (default is `llama3:latest`):
    ```bash
    ollama pull llama3
    ```

3.  **Run the Evaluator:**
    ```bash
    cd Score
    python3 llm_evaluator_llama3.py
    ```
    *   This script will analyze contracts in the `buggy/` directory.
    *   Results will be saved to `tool_results/LLM/analyzed_buggy_contracts`.

### 3. Analysis

Analysis scripts are located in `Score/Benchmark analysis/`. You can use them to compare results against ground truth and generate metrics.

```bash
cd Score/Benchmark analysis
# Example: Compare results
python3 compare_with_ground_truth.py
```

## Project Structure

*   `Score/`: Main source code.
    *   `solidifi.py`: Core bug injection tool.
    *   `llm_evaluator_llama3.py`: Script to evaluate contracts using Llama 3 via Ollama.
    *   `buggy/`: Generated buggy contracts.
    *   `tool_results/`: Output directory for analysis tools.
*   `Score/Benchmark analysis/`: Scripts for calculating precision, recall, and F1-scores.
