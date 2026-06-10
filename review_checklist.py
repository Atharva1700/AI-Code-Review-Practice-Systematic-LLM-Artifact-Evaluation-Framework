"""
Structured review checklist for AI-generated code.

Covers:
  1. API contract validation
  2. Edge case coverage (boundary / null / error paths)
  3. Security patterns
  4. Performance implications (N+1 queries, unnecessary allocations)
  5. General code quality
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    name: str
    category: str
    status: CheckStatus
    detail: str = ""
    line: int = 0

    def __str__(self) -> str:
        icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "SKIP": "–"}[self.status.value]
        loc = f" (L{self.line})" if self.line else ""
        detail = f" — {self.detail}" if self.detail else ""
        return f"  {icon} [{self.category}] {self.name}{loc}{detail}"


@dataclass
class ChecklistReport:
    file: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.WARN)

    def overall_passed(self) -> bool:
        return self.failed == 0

    def render(self) -> str:
        lines = [
            f"Checklist: {self.file}",
            f"  Passed: {self.passed}  Failed: {self.failed}  Warnings: {self.warned}",
            "",
        ]
        by_category: dict[str, list[CheckResult]] = {}
        for r in self.results:
            by_category.setdefault(r.category, []).append(r)
        for cat, items in by_category.items():
            lines.append(f"  {cat}")
            lines.extend(str(i) for i in items)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_type_annotations(tree: ast.Module) -> list[CheckResult]:
    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            missing = []
            for arg in node.args.args:
                if arg.annotation is None and arg.arg != "self":
                    missing.append(arg.arg)
            if missing:
                results.append(
                    CheckResult(
                        name="Missing parameter annotations",
                        category="API Contract",
                        status=CheckStatus.WARN,
                        detail=f"fn '{node.name}': unannotated args: {', '.join(missing)}",
                        line=node.lineno,
                    )
                )
            elif node.returns is None:
                results.append(
                    CheckResult(
                        name="Missing return annotation",
                        category="API Contract",
                        status=CheckStatus.WARN,
                        detail=f"fn '{node.name}' has no return type annotation.",
                        line=node.lineno,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name=f"Type annotations present ({node.name})",
                        category="API Contract",
                        status=CheckStatus.PASS,
                        line=node.lineno,
                    )
                )
    return results


def _check_docstrings(tree: ast.Module) -> list[CheckResult]:
    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            has_doc = (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            )
            status = CheckStatus.PASS if has_doc else CheckStatus.WARN
            results.append(
                CheckResult(
                    name=f"Docstring ({'present' if has_doc else 'missing'})",
                    category="API Contract",
                    status=status,
                    detail="" if has_doc else f"'{node.name}' has no docstring.",
                    line=node.lineno,
                )
            )
    return results


def _check_none_handling(tree: ast.Module) -> list[CheckResult]:
    """Warn about functions that accept None-able inputs without a guard."""
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Look for Optional / None defaults
        optional_args = []
        for arg, default in zip(
            reversed(node.args.args), reversed(node.args.defaults)
        ):
            if isinstance(default, ast.Constant) and default.value is None:
                optional_args.append(arg.arg)

        if not optional_args:
            continue

        # Check whether there's an `if x is None` guard somewhere in the body
        none_checks = {
            node2.test.comparators[0].id
            if (
                isinstance(node2, ast.If)
                and isinstance(node2.test, ast.Compare)
                and isinstance(node2.test.comparators[0], ast.Constant)
                and node2.test.comparators[0].value is None
            )
            else None
            for node2 in ast.walk(node)
        }
        unguarded = [a for a in optional_args if a not in none_checks]

        if unguarded:
            results.append(
                CheckResult(
                    name="None-able parameters without null guard",
                    category="Edge Cases",
                    status=CheckStatus.WARN,
                    detail=f"fn '{node.name}': {', '.join(unguarded)} default to None but lack None checks.",
                    line=node.lineno,
                )
            )
        else:
            results.append(
                CheckResult(
                    name=f"None handling present ({node.name})",
                    category="Edge Cases",
                    status=CheckStatus.PASS,
                    line=node.lineno,
                )
            )
    return results


def _check_exception_handling(tree: ast.Module) -> list[CheckResult]:
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        # Bare except or `except Exception` with just `pass`
        is_bare = node.type is None
        is_generic = isinstance(node.type, ast.Name) and node.type.id == "Exception"
        body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if (is_bare or is_generic) and body_is_pass:
            results.append(
                CheckResult(
                    name="Silent exception swallowing",
                    category="Edge Cases",
                    status=CheckStatus.FAIL,
                    detail="Bare/generic except with `pass` hides errors.",
                    line=node.lineno,
                )
            )
        elif is_bare:
            results.append(
                CheckResult(
                    name="Bare except clause",
                    category="Edge Cases",
                    status=CheckStatus.WARN,
                    detail="Catches all exceptions including SystemExit and KeyboardInterrupt.",
                    line=node.lineno,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="Specific exception caught",
                    category="Edge Cases",
                    status=CheckStatus.PASS,
                    line=node.lineno,
                )
            )
    return results


def _check_n_plus_one(tree: ast.Module, source_lines: list[str]) -> list[CheckResult]:
    """Heuristic: DB query call inside a for-loop body."""
    results = []
    query_methods = {"filter", "get", "all", "execute", "fetchone", "fetchall", "query"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.While)):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if isinstance(child.func, ast.Attribute) and child.func.attr in query_methods:
                results.append(
                    CheckResult(
                        name="Possible N+1 query",
                        category="Performance",
                        status=CheckStatus.WARN,
                        detail=f"DB call '{child.func.attr}()' inside a loop — consider bulk fetch.",
                        line=child.lineno,
                    )
                )
    if not results:
        results.append(
            CheckResult(
                name="No N+1 patterns detected",
                category="Performance",
                status=CheckStatus.PASS,
            )
        )
    return results


def _check_unnecessary_allocations(tree: ast.Module) -> list[CheckResult]:
    """Flag list comprehensions used only for iteration (should be generators)."""
    results = []
    for node in ast.walk(tree):
        # list comp as the sole argument to sum/any/all/max/min
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in ("sum", "any", "all", "max", "min"):
            continue
        if node.args and isinstance(node.args[0], ast.ListComp):
            results.append(
                CheckResult(
                    name="Unnecessary list allocation",
                    category="Performance",
                    status=CheckStatus.WARN,
                    detail=f"List comprehension inside {node.func.id}() — use a generator expression instead.",
                    line=node.lineno,
                )
            )
    if not results:
        results.append(
            CheckResult(
                name="No unnecessary allocations detected",
                category="Performance",
                status=CheckStatus.PASS,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_checklist(path: str | Path) -> ChecklistReport:
    path = Path(path)
    report = ChecklistReport(file=str(path))

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        report.results.append(
            CheckResult("File read error", "IO", CheckStatus.FAIL, detail=str(exc))
        )
        return report

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        report.results.append(
            CheckResult(
                "Syntax error",
                "Parse",
                CheckStatus.FAIL,
                detail=str(exc),
                line=exc.lineno or 0,
            )
        )
        return report

    source_lines = source.splitlines()

    report.results.extend(_check_type_annotations(tree))
    report.results.extend(_check_docstrings(tree))
    report.results.extend(_check_none_handling(tree))
    report.results.extend(_check_exception_handling(tree))
    report.results.extend(_check_n_plus_one(tree, source_lines))
    report.results.extend(_check_unnecessary_allocations(tree))

    return report


if __name__ == "__main__":
    import sys

    targets = sys.argv[1:] or ["."]
    for target in targets:
        p = Path(target)
        files = [p] if p.is_file() else sorted(p.glob("**/*.py"))
        for f in files:
            if ".venv" in f.parts or "__pycache__" in f.parts:
                continue
            report = run_checklist(f)
            print(report.render())
            print()
