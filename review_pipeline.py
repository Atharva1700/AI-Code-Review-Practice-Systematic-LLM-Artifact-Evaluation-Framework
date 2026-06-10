"""
AI Code Review Pipeline

Orchestrates:
  1. AST-based hallucination detection
  2. Security scanning
  3. Structured review checklist
  4. Metrics tracking

Usage:
    python -m src.pipeline.review_pipeline path/to/file_or_dir
    python -m src.pipeline.review_pipeline --json path/to/file.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src.analyzer.ast_analyzer import AnalysisResult, analyze_file, analyze_directory
from src.analyzer.security_checker import SecurityResult, scan_file, scan_directory
from src.checklist.review_checklist import ChecklistReport, run_checklist


@dataclass
class ReviewRecord:
    """Single file review record persisted for metrics tracking."""

    file: str
    timestamp: str
    ast_errors: int
    ast_warnings: int
    security_critical: int
    security_high: int
    checklist_failed: int
    checklist_warned: int
    overall_passed: bool
    duration_ms: float


@dataclass
class PipelineResult:
    file: str
    ast: AnalysisResult
    security: SecurityResult
    checklist: ChecklistReport
    duration_ms: float

    @property
    def passed(self) -> bool:
        return (
            self.ast.passed()
            and self.security.passed()
            and self.checklist.overall_passed()
        )

    def to_record(self) -> ReviewRecord:
        return ReviewRecord(
            file=self.file,
            timestamp=datetime.now(timezone.utc).isoformat(),
            ast_errors=self.ast.error_count,
            ast_warnings=self.ast.warning_count,
            security_critical=self.security.critical_count,
            security_high=self.security.high_count,
            checklist_failed=self.checklist.failed,
            checklist_warned=self.checklist.warned,
            overall_passed=self.passed,
            duration_ms=self.duration_ms,
        )

    def render(self, verbose: bool = False) -> str:
        status = "✓ PASSED" if self.passed else "✗ FAILED"
        lines = [
            f"{'=' * 64}",
            f"  Review: {self.file}",
            f"  Result: {status}  ({self.duration_ms:.0f} ms)",
            f"{'=' * 64}",
        ]

        # AST summary
        lines.append(
            f"\n[AST Analysis]  errors={self.ast.error_count}  warnings={self.ast.warning_count}"
        )
        if verbose or self.ast.error_count:
            for issue in self.ast.issues:
                tag = f"[{issue.severity.upper()}]"
                lines.append(f"  {tag} L{issue.line} ({issue.category}) {issue.message}")

        # Security summary
        lines.append(
            f"\n[Security Scan]  critical={self.security.critical_count}  high={self.security.high_count}"
        )
        if verbose or self.security.critical_count or self.security.high_count:
            for issue in self.security.issues:
                tag = f"[{issue.severity.upper()}]"
                cwe = f" {issue.cwe}" if issue.cwe else ""
                lines.append(f"  {tag}{cwe} L{issue.line} {issue.message}")

        # Checklist summary
        lines.append(
            f"\n[Checklist]  passed={self.checklist.passed}  failed={self.checklist.failed}  warned={self.checklist.warned}"
        )
        if verbose or self.checklist.failed:
            from src.checklist.review_checklist import CheckStatus
            for r in self.checklist.results:
                if verbose or r.status in (CheckStatus.FAIL, CheckStatus.WARN):
                    lines.append(str(r))

        return "\n".join(lines)

    def to_json(self) -> dict:
        return {
            "file": self.file,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "ast": {
                "errors": self.ast.error_count,
                "warnings": self.ast.warning_count,
                "issues": [
                    {
                        "severity": i.severity,
                        "category": i.category,
                        "message": i.message,
                        "line": i.line,
                        "suggestion": i.suggestion,
                    }
                    for i in self.ast.issues
                ],
            },
            "security": {
                "critical": self.security.critical_count,
                "high": self.security.high_count,
                "issues": [
                    {
                        "severity": i.severity,
                        "category": i.category,
                        "message": i.message,
                        "line": i.line,
                        "cwe": i.cwe,
                        "recommendation": i.recommendation,
                    }
                    for i in self.security.issues
                ],
            },
            "checklist": {
                "passed": self.checklist.passed,
                "failed": self.checklist.failed,
                "warned": self.checklist.warned,
                "results": [
                    {
                        "name": r.name,
                        "category": r.category,
                        "status": r.status.value,
                        "detail": r.detail,
                        "line": r.line,
                    }
                    for r in self.checklist.results
                ],
            },
        }


def review_file(path: str | Path) -> PipelineResult:
    path = Path(path)
    t0 = time.perf_counter()
    ast_result = analyze_file(path)
    sec_result = scan_file(path)
    checklist_result = run_checklist(path)
    duration = (time.perf_counter() - t0) * 1000
    return PipelineResult(
        file=str(path),
        ast=ast_result,
        security=sec_result,
        checklist=checklist_result,
        duration_ms=duration,
    )


def review_directory(root: str | Path) -> list[PipelineResult]:
    root = Path(root)
    results = []
    for path in sorted(root.glob("**/*.py")):
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        results.append(review_file(path))
    return results


# ---------------------------------------------------------------------------
# Metrics tracker
# ---------------------------------------------------------------------------

METRICS_FILE = Path("review_metrics.jsonl")


def append_metrics(records: list[ReviewRecord]) -> None:
    with METRICS_FILE.open("a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(asdict(rec)) + "\n")


def load_metrics() -> list[ReviewRecord]:
    if not METRICS_FILE.exists():
        return []
    records = []
    with METRICS_FILE.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(ReviewRecord(**json.loads(line)))
    return records


def print_metrics_summary(records: list[ReviewRecord]) -> None:
    if not records:
        print("No review records found.")
        return

    total = len(records)
    passed = sum(1 for r in records if r.overall_passed)
    acceptance_rate = passed / total * 100
    avg_duration = sum(r.duration_ms for r in records) / total

    print(f"\n{'=' * 50}")
    print(f"  AI Code Review Metrics  ({total} reviews)")
    print(f"{'=' * 50}")
    print(f"  First-draft acceptance rate : {acceptance_rate:.1f}%")
    print(f"  Average review time         : {avg_duration:.0f} ms")
    print(f"  Total passed                : {passed}")
    print(f"  Total failed                : {total - passed}")

    # Security issues breakdown
    critical_total = sum(r.security_critical for r in records)
    print(f"  Security critical issues    : {critical_total}")
    print(f"{'=' * 50}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AI Code Review Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              python -m src.pipeline.review_pipeline src/
              python -m src.pipeline.review_pipeline --json mymodule.py
              python -m src.pipeline.review_pipeline --metrics
            """
        ),
    )
    p.add_argument("targets", nargs="*", help="Files or directories to review")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("--verbose", "-v", action="store_true", help="Show all checklist items")
    p.add_argument("--metrics", action="store_true", help="Print cumulative metrics summary")
    p.add_argument(
        "--no-track", action="store_true", help="Skip appending results to metrics file"
    )
    return p


import textwrap


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.metrics:
        print_metrics_summary(load_metrics())
        return 0

    targets = args.targets or ["."]
    all_results: list[PipelineResult] = []

    for target in targets:
        p = Path(target)
        if p.is_file():
            all_results.append(review_file(p))
        elif p.is_dir():
            all_results.extend(review_directory(p))
        else:
            print(f"Warning: '{target}' not found, skipping.", file=sys.stderr)

    if not all_results:
        print("No Python files found.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([r.to_json() for r in all_results], indent=2))
    else:
        for result in all_results:
            print(result.render(verbose=args.verbose))
            print()

    if not args.no_track:
        append_metrics([r.to_record() for r in all_results])

    failed = sum(1 for r in all_results if not r.passed)
    if not args.json:
        total = len(all_results)
        print(f"{'=' * 64}")
        print(f"  Summary: {total - failed}/{total} files passed")
        print(f"{'=' * 64}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
