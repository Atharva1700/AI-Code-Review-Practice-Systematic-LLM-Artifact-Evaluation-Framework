# AI Code Review Framework

A systematic, multi-layer framework for critically reviewing AI-generated code — catching hallucinations, security vulnerabilities, and quality issues before they reach production.

> **Results from 3 months of real usage:** 47 AI-generated code reviews tracked · 89% first-draft acceptance rate · zero production bugs from AI-generated code.

---

## Overview

This project addresses a core challenge with LLM-assisted development: AI code generators (Claude Code, GitHub Copilot, GPT-4) produce plausible-looking code that can contain subtle errors — undefined imports, incorrect API signatures, security vulnerabilities, and missing edge-case handling. This framework provides an automated review layer that catches these issues systematically.

```
┌────────────────────────────────────────────────────────┐
│              AI Code Review Pipeline                   │
│                                                        │
│  [AI-generated code]                                   │
│         │                                              │
│         ▼                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │  AST Analyzer   │  │  Security    │  │ Review   │  │
│  │  · hallucinated │  │  · secrets   │  │Checklist │  │
│  │    imports      │  │  · SQLi      │  │ · API    │  │
│  │  · bad sigs     │  │  · cmd inj   │  │   contract│  │
│  │  · undef names  │  │  · pickle    │  │ · edges  │  │
│  └─────────────────┘  └──────────────┘  │ · perf   │  │
│         │                   │           └──────────┘  │
│         └───────────────────┘──────────────┘          │
│                         │                              │
│                  ┌──────▼──────┐                       │
│                  │   Report +  │                       │
│                  │   Metrics   │                       │
│                  └─────────────┘                       │
└────────────────────────────────────────────────────────┘
```

---

## Features

### 1. AST-based Hallucination Detector (`src/analyzer/ast_analyzer.py`)
- **Undefined imports** — tries to actually import each module at analysis time
- **Hallucinated from-imports** — verifies each `from X import Y` attribute exists on `X`
- **Incorrect method signatures** — checks call-site arity against known stdlib signatures
- **Undefined name usage** — flags names used before assignment or import
- **Missing return statements** — warns when a return annotation exists but no `return` is found

### 2. Security Pattern Scanner (`src/analyzer/security_checker.py`)
- **Hardcoded secrets** — regex patterns for passwords, API keys, tokens (CWE-798)
- **SQL injection** — detects `%`-formatted and concatenated queries passed to `execute()` (CWE-89)
- **Command injection** — flags `subprocess` calls with `shell=True` (CWE-78)
- **Insecure deserialization** — catches `pickle.loads()` and `yaml.load()` without SafeLoader (CWE-502)
- **Weak cryptography** — warns on `hashlib.md5()` / `hashlib.sha1()` (CWE-327)

### 3. Structured Review Checklist (`src/checklist/review_checklist.py`)
| Category | Checks |
|---|---|
| **API Contract** | Type annotations, return types, docstrings |
| **Edge Cases** | None-parameter guards, exception handling quality |
| **Performance** | N+1 query patterns, unnecessary list allocations |

### 4. Review Pipeline (`src/pipeline/review_pipeline.py`)
- Orchestrates all three layers into a single pass
- JSON output mode for CI integration
- Metrics tracking to `review_metrics.jsonl` (JSONL format, one record per review)
- Cumulative statistics: acceptance rate, avg review time, security issue counts

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/yourusername/ai-code-review-framework
cd ai-code-review-framework
pip install -e ".[dev]"

# Review a single file
python -m src.pipeline.review_pipeline path/to/your_module.py

# Review a directory
python -m src.pipeline.review_pipeline src/

# Verbose output (show all checklist items, not just failures)
python -m src.pipeline.review_pipeline --verbose mymodule.py

# JSON output (for CI / tooling integration)
python -m src.pipeline.review_pipeline --json src/ | jq '.[] | select(.passed == false)'

# View cumulative metrics
python -m src.pipeline.review_pipeline --metrics
```

### Try the examples

```bash
# Clean, well-structured AI-generated code:
python -m src.pipeline.review_pipeline examples/example_good.py

# Code with 8 intentional issues — watch the pipeline catch them:
python -m src.pipeline.review_pipeline --verbose examples/example_bad.py
```

---

## Running Tests

```bash
pytest                          # run all tests
pytest -v                       # verbose
pytest tests/ --cov=src         # with coverage
```

The test suite covers:
- Hallucination detection (undefined imports, bad from-imports, signature mismatches)
- Security patterns (SQL injection, hardcoded secrets, command injection, deserialization)
- Checklist logic (None guards, bare except, N+1, unnecessary allocations)
- Pipeline integration (end-to-end on fixture files)
- Edge cases (empty files, unicode, deeply nested code, nonexistent files)

---

## Workflow Integration

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
python -m src.pipeline.review_pipeline --no-track $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')
```

### GitHub Actions

The included `.github/workflows/ci.yml` runs tests across Python 3.11/3.12 and then runs the pipeline on the source directory itself as a self-review step.

### VS Code Task

```json
{
  "label": "AI Review: current file",
  "type": "shell",
  "command": "python -m src.pipeline.review_pipeline --verbose ${file}",
  "group": "test"
}
```

---

## Project Structure

```
ai-code-review-framework/
├── src/
│   ├── analyzer/
│   │   ├── ast_analyzer.py       # Hallucination detection via AST walking
│   │   └── security_checker.py  # Security pattern scanning
│   ├── checklist/
│   │   └── review_checklist.py  # Structured quality checklist
│   └── pipeline/
│       └── review_pipeline.py   # Orchestrator + metrics tracking
├── tests/
│   └── test_review_framework.py # Full pytest suite
├── examples/
│   ├── example_good.py          # Well-structured AI-generated code
│   └── example_bad.py           # Code with intentional issues
├── .github/workflows/ci.yml
├── pyproject.toml
└── README.md
```

---

## Metrics

The pipeline appends a JSONL record to `review_metrics.jsonl` after each run (use `--no-track` to skip). View aggregate stats:

```bash
python -m src.pipeline.review_pipeline --metrics
```

Sample output after 47 reviews:

```
==================================================
  AI Code Review Metrics  (47 reviews)
==================================================
  First-draft acceptance rate : 89.4%
  Average review time         : 42 ms
  Total passed                : 42
  Total failed                : 5
  Security critical issues    : 0
==================================================
```

---

## Design Decisions

**Why AST over regex?** Regex-based linters miss context; AST analysis understands scope, call sites, and structure. This lets us catch "the function *has* an annotation but *no* return" rather than just "does the word `return` appear."

**Why try-import at analysis time?** LLMs frequently invent plausible-sounding module names (`os.makedirs_recursive`, `requests.get_json`). Attempting the real import is the most reliable way to catch these.

**Why JSONL for metrics?** Append-only, line-oriented, trivially parseable with `jq` or Python. No database required, works well with git.

---

## License

MIT
