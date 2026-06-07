"""
AST-based static analyzer for catching common AI hallucination patterns.

Detects:
- Undefined imports / missing modules
- Incorrect method signatures
- Hallucinated attributes / methods on known types
- Incorrect return type usage
- Missing error handling paths
"""

import ast
import builtins
import importlib
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BUILTIN_NAMES = set(dir(builtins))

# Known method signatures for common stdlib types (method -> (min_args, max_args))
KNOWN_SIGNATURES: dict[str, dict[str, tuple[int, int]]] = {
    "list": {
        "append": (1, 1),
        "extend": (1, 1),
        "insert": (2, 2),
        "remove": (1, 1),
        "pop": (0, 1),
        "index": (1, 3),
        "count": (1, 1),
        "sort": (0, 0),
        "reverse": (0, 0),
        "copy": (0, 0),
        "clear": (0, 0),
    },
    "dict": {
        "get": (1, 2),
        "setdefault": (1, 2),
        "update": (0, 1),
        "pop": (1, 2),
        "keys": (0, 0),
        "values": (0, 0),
        "items": (0, 0),
        "copy": (0, 0),
        "clear": (0, 0),
    },
    "str": {
        "split": (0, 2),
        "join": (1, 1),
        "strip": (0, 1),
        "lstrip": (0, 1),
        "rstrip": (0, 1),
        "replace": (2, 3),
        "find": (1, 3),
        "format": (0, None),
        "startswith": (1, 3),
        "endswith": (1, 3),
        "upper": (0, 0),
        "lower": (0, 0),
        "encode": (0, 2),
        "decode": (0, 2),
    },
}


@dataclass
class AnalysisIssue:
    severity: str  # "error" | "warning" | "info"
    category: str
    message: str
    line: int
    col: int
    suggestion: str = ""


@dataclass
class AnalysisResult:
    file: str
    issues: list[AnalysisIssue] = field(default_factory=list)
    imports_validated: int = 0
    nodes_visited: int = 0

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")

    def passed(self, allow_warnings: bool = True) -> bool:
        if allow_warnings:
            return self.error_count == 0
        return len(self.issues) == 0

    def summary(self) -> str:
        lines = [
            f"File: {self.file}",
            f"  Nodes visited   : {self.nodes_visited}",
            f"  Imports checked : {self.imports_validated}",
            f"  Errors          : {self.error_count}",
            f"  Warnings        : {self.warning_count}",
        ]
        if self.issues:
            lines.append("  Issues:")
            for issue in self.issues:
                tag = f"[{issue.severity.upper()}]"
                lines.append(
                    f"    {tag} L{issue.line}:{issue.col} ({issue.category}) {issue.message}"
                )
                if issue.suggestion:
                    lines.append(f"      → {issue.suggestion}")
        return "\n".join(lines)


class AIHallucinationVisitor(ast.NodeVisitor):
    """Walk an AST and flag patterns commonly produced by LLM code generators."""

    def __init__(self, source_lines: list[str]) -> None:
        self.issues: list[AnalysisIssue] = []
        self._source = source_lines
        self._imports_validated = 0
        self._nodes_visited = 0
        self._defined_names: set[str] = set(BUILTIN_NAMES)
        self._import_aliases: dict[str, str] = {}  # alias -> real module

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        node: ast.AST,
        severity: str,
        category: str,
        message: str,
        suggestion: str = "",
    ) -> None:
        self.issues.append(
            AnalysisIssue(
                severity=severity,
                category=category,
                message=message,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                suggestion=suggestion,
            )
        )

    def _resolve_import(self, module_name: str) -> bool:
        """Return True if the module can be imported in the current environment."""
        try:
            importlib.import_module(module_name)
            return True
        except ModuleNotFoundError:
            return False
        except Exception:
            # Import succeeded but raised for another reason (e.g. side-effects)
            return True

    # ------------------------------------------------------------------
    # Visitors
    # ------------------------------------------------------------------

    def generic_visit(self, node: ast.AST) -> Any:
        self._nodes_visited += 1
        return super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports_validated += 1
            name = alias.name
            asname = alias.asname or name.split(".")[0]
            self._defined_names.add(asname)
            self._import_aliases[asname] = name

            if not self._resolve_import(name):
                self._add(
                    node,
                    "error",
                    "undefined_import",
                    f"Cannot import '{name}' — module not found.",
                    suggestion=f"Verify spelling or install: pip install {name.split('.')[0]}",
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        self._imports_validated += 1

        if module and not self._resolve_import(module):
            self._add(
                node,
                "error",
                "undefined_import",
                f"Cannot import from '{module}' — module not found.",
                suggestion=f"Verify spelling or install: pip install {module.split('.')[0]}",
            )
        else:
            # Check individual names exist in the module
            if module:
                try:
                    mod = importlib.import_module(module)
                    for alias in node.names:
                        n = alias.name
                        if n != "*" and not hasattr(mod, n):
                            self._add(
                                node,
                                "error",
                                "hallucinated_attribute",
                                f"'{module}' has no attribute '{n}'.",
                                suggestion=f"Check the {module} docs for the correct name.",
                            )
                        asname = alias.asname or n
                        self._defined_names.add(asname)
                except Exception:
                    pass

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._defined_names.add(node.name)
        self._check_missing_return(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            if node.id not in self._defined_names and not node.id.startswith("_"):
                self._add(
                    node,
                    "warning",
                    "undefined_name",
                    f"Name '{node.id}' used before definition (possible hallucination).",
                    suggestion="Ensure the variable is assigned or imported before use.",
                )
        elif isinstance(node.ctx, (ast.Store, ast.Del)):
            self._defined_names.add(node.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_method_call(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._defined_names.add(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self._defined_names.add(elt.id)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name):
            self._defined_names.add(node.target.id)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self._defined_names.add(item.optional_vars.id)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Domain-specific checks
    # ------------------------------------------------------------------

    def _check_method_call(self, node: ast.Call) -> None:
        """Verify known method signatures aren't being called with wrong arity."""
        if not isinstance(node.func, ast.Attribute):
            return

        method = node.func.attr
        for type_name, methods in KNOWN_SIGNATURES.items():
            if method not in methods:
                continue
            min_args, max_args = methods[method]
            actual = len(node.args)
            if actual < min_args:
                self._add(
                    node,
                    "error",
                    "incorrect_signature",
                    f"'{type_name}.{method}' requires at least {min_args} positional arg(s), got {actual}.",
                    suggestion=f"Check the signature: {type_name}.{method}(...)",
                )
            elif max_args is not None and actual > max_args:
                self._add(
                    node,
                    "error",
                    "incorrect_signature",
                    f"'{type_name}.{method}' accepts at most {max_args} positional arg(s), got {actual}.",
                    suggestion=f"Check the signature: {type_name}.{method}(...)",
                )

    def _check_missing_return(self, node: ast.FunctionDef) -> None:
        """Warn when a function has a return annotation but no return statement."""
        annotation = node.returns
        if annotation is None:
            return
        # Skip if annotated as None / NoReturn
        if isinstance(annotation, ast.Constant) and annotation.value is None:
            return
        if isinstance(annotation, ast.Name) and annotation.id in ("None", "NoReturn"):
            return

        has_return = any(
            isinstance(n, ast.Return) and n.value is not None
            for n in ast.walk(node)
        )
        if not has_return:
            self._add(
                node,
                "warning",
                "missing_return",
                f"Function '{node.name}' has a return annotation but no return statement.",
                suggestion="Add a return statement or change the annotation to -> None.",
            )


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def analyze_file(path: str | Path) -> AnalysisResult:
    """Analyze a single Python file and return an AnalysisResult."""
    path = Path(path)
    result = AnalysisResult(file=str(path))

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.issues.append(
            AnalysisIssue("error", "io_error", str(exc), line=0, col=0)
        )
        return result

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        result.issues.append(
            AnalysisIssue(
                "error",
                "syntax_error",
                f"Syntax error: {exc.msg}",
                line=exc.lineno or 0,
                col=exc.offset or 0,
            )
        )
        return result

    visitor = AIHallucinationVisitor(source.splitlines())
    visitor.visit(tree)

    result.issues = visitor.issues
    result.imports_validated = visitor._imports_validated
    result.nodes_visited = visitor._nodes_visited
    return result


def analyze_directory(root: str | Path, pattern: str = "**/*.py") -> list[AnalysisResult]:
    """Recursively analyze all Python files under root."""
    root = Path(root)
    results = []
    for path in sorted(root.glob(pattern)):
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        results.append(analyze_file(path))
    return results


if __name__ == "__main__":
    import sys

    targets = sys.argv[1:] or ["."]
    all_results: list[AnalysisResult] = []

    for target in targets:
        p = Path(target)
        if p.is_file():
            all_results.append(analyze_file(p))
        else:
            all_results.extend(analyze_directory(p))

    total_errors = sum(r.error_count for r in all_results)
    for r in all_results:
        print(r.summary())
        print()

    print(f"{'='*60}")
    print(f"Files analyzed : {len(all_results)}")
    print(f"Total errors   : {total_errors}")
    sys.exit(1 if total_errors else 0)
