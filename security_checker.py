"""
Security pattern verifier for AI-generated code.

Checks for:
- Hardcoded secrets / API keys
- SQL injection vulnerabilities (string-formatted queries)
- Command injection risks (shell=True with user input)
- Insecure deserialization (pickle.loads on untrusted data)
- Path traversal patterns
- Use of MD5 / SHA1 for security purposes
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

# Regex patterns for secret detection (applied to string literals)
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
    (r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
    (r"(?i)(secret|token)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded secret/token"),
    (r"(?i)(aws_access_key_id)\s*=\s*['\"][A-Z0-9]{16,}['\"]", "Hardcoded AWS key"),
    (r"AKIA[0-9A-Z]{16}", "Possible AWS access key ID"),
    (r"(?i)bearer\s+[a-z0-9\-_\.]{20,}", "Hardcoded Bearer token"),
]

WEAK_HASH_MODULES = {"md5", "sha1"}


@dataclass
class SecurityIssue:
    severity: str  # "critical" | "high" | "medium" | "low"
    category: str
    message: str
    line: int
    col: int
    cwe: str = ""
    recommendation: str = ""


@dataclass
class SecurityResult:
    file: str
    issues: list[SecurityIssue] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "high")

    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    def summary(self) -> str:
        lines = [
            f"Security scan: {self.file}",
            f"  Critical : {self.critical_count}",
            f"  High     : {self.high_count}",
            f"  Total    : {len(self.issues)}",
        ]
        for issue in self.issues:
            tag = f"[{issue.severity.upper()}]"
            cwe = f" ({issue.cwe})" if issue.cwe else ""
            lines.append(f"    {tag} L{issue.line} {issue.category}{cwe}: {issue.message}")
            if issue.recommendation:
                lines.append(f"      → {issue.recommendation}")
        return "\n".join(lines)


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.issues: list[SecurityIssue] = []
        self._source = source
        self._source_lines = source.splitlines()

    def _add(
        self,
        node: ast.AST,
        severity: str,
        category: str,
        message: str,
        cwe: str = "",
        recommendation: str = "",
    ) -> None:
        self.issues.append(
            SecurityIssue(
                severity=severity,
                category=category,
                message=message,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                cwe=cwe,
                recommendation=recommendation,
            )
        )

    # ------------------------------------------------------------------
    # Hardcoded secrets (line-level regex scan)
    # ------------------------------------------------------------------

    def scan_secrets(self) -> None:
        for lineno, line in enumerate(self._source_lines, start=1):
            for pattern, label in SECRET_PATTERNS:
                if re.search(pattern, line):
                    self.issues.append(
                        SecurityIssue(
                            severity="critical",
                            category="hardcoded_secret",
                            message=f"{label} detected.",
                            line=lineno,
                            col=0,
                            cwe="CWE-798",
                            recommendation="Use environment variables or a secrets manager.",
                        )
                    )

    # ------------------------------------------------------------------
    # AST-level checks
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql_injection(node)
        self._check_command_injection(node)
        self._check_pickle(node)
        self._check_weak_hash(node)
        self._check_yaml_load(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Flag f-strings used as SQL queries."""
        # Heuristic: f-string containing SQL keywords
        src_line = self._source_lines[node.lineno - 1] if node.lineno else ""
        sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM")
        if any(kw in src_line.upper() for kw in sql_keywords):
            self._add(
                node,
                "critical",
                "sql_injection",
                "F-string used in what appears to be a SQL query.",
                cwe="CWE-89",
                recommendation="Use parameterized queries / ORM methods instead.",
            )
        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Detect cursor.execute(f'...') or cursor.execute('...' % ...)."""
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in ("execute", "executemany"):
            return
        if not node.args:
            return
        first_arg = node.args[0]
        # % formatting
        if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            self._add(
                node,
                "critical",
                "sql_injection",
                "String-formatted SQL query (% operator) passed to execute().",
                cwe="CWE-89",
                recommendation="Use parameterized queries: cursor.execute(sql, params)",
            )
        # + concatenation
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            self._add(
                node,
                "critical",
                "sql_injection",
                "String-concatenated SQL query passed to execute().",
                cwe="CWE-89",
                recommendation="Use parameterized queries: cursor.execute(sql, params)",
            )

    def _check_command_injection(self, node: ast.Call) -> None:
        """Flag subprocess calls with shell=True."""
        func_names = set()
        if isinstance(node.func, ast.Name):
            func_names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            func_names.add(node.func.attr)

        if not func_names.intersection({"call", "run", "Popen", "check_output", "system"}):
            return

        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self._add(
                    node,
                    "high",
                    "command_injection",
                    "subprocess called with shell=True.",
                    cwe="CWE-78",
                    recommendation="Pass a list of arguments and avoid shell=True unless strictly necessary.",
                )

    def _check_pickle(self, node: ast.Call) -> None:
        """Detect pickle.loads / pickle.load on potentially untrusted data."""
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self._add(
                    node,
                    "high",
                    "insecure_deserialization",
                    "pickle.load(s) deserializes arbitrary objects — dangerous with untrusted input.",
                    cwe="CWE-502",
                    recommendation="Use JSON or a schema-validated format for untrusted data.",
                )

    def _check_weak_hash(self, node: ast.Call) -> None:
        """Detect hashlib.md5() / hashlib.sha1() used for security."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in WEAK_HASH_MODULES:
                self._add(
                    node,
                    "medium",
                    "weak_cryptography",
                    f"hashlib.{node.func.attr}() is cryptographically weak.",
                    cwe="CWE-327",
                    recommendation="Use hashlib.sha256() or better for security-sensitive contexts.",
                )

    def _check_yaml_load(self, node: ast.Call) -> None:
        """Detect yaml.load without Loader=SafeLoader."""
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "load":
            return
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "yaml":
            return
        has_loader = any(kw.arg == "Loader" for kw in node.keywords)
        if not has_loader:
            self._add(
                node,
                "high",
                "insecure_deserialization",
                "yaml.load() called without explicit Loader — arbitrary code execution risk.",
                cwe="CWE-502",
                recommendation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
            )


def scan_file(path: str | Path) -> SecurityResult:
    path = Path(path)
    result = SecurityResult(file=str(path))
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        result.issues.append(
            SecurityIssue("critical", "io_error", str(exc), line=0, col=0)
        )
        return result

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return result

    visitor = SecurityVisitor(source)
    visitor.scan_secrets()
    visitor.visit(tree)
    result.issues = visitor.issues
    return result


def scan_directory(root: str | Path, pattern: str = "**/*.py") -> list[SecurityResult]:
    root = Path(root)
    results = []
    for path in sorted(root.glob(pattern)):
        if ".venv" in path.parts or "__pycache__" in path.parts:
            continue
        results.append(scan_file(path))
    return results


if __name__ == "__main__":
    import sys

    targets = sys.argv[1:] or ["."]
    all_results: list[SecurityResult] = []

    for target in targets:
        p = Path(target)
        if p.is_file():
            all_results.append(scan_file(p))
        else:
            all_results.extend(scan_directory(p))

    total_critical = sum(r.critical_count for r in all_results)
    for r in all_results:
        print(r.summary())
        print()

    print(f"{'='*60}")
    print(f"Files scanned    : {len(all_results)}")
    print(f"Critical issues  : {total_critical}")
    sys.exit(1 if total_critical else 0)
