"""
pytest test suite for the AI Code Review Framework.

Tests:
  - AST analyzer: hallucination detection, import validation, signature checks
  - Security checker: SQL injection, hardcoded secrets, command injection
  - Checklist: edge-case coverage, None handling, exception patterns
  - Pipeline: end-to-end review on fixture files
"""

import textwrap
from pathlib import Path

import pytest

from src.analyzer.ast_analyzer import analyze_file, AnalysisResult
from src.analyzer.security_checker import scan_file, SecurityResult
from src.checklist.review_checklist import run_checklist, ChecklistReport, CheckStatus
from src.pipeline.review_pipeline import review_file, PipelineResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_tmp(tmp_path: Path, name: str, code: str) -> Path:
    """Write dedented code to a temp file and return its path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# AST Analyzer Tests
# ---------------------------------------------------------------------------


class TestASTAnalyzer:
    def test_valid_file_no_issues(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "clean.py",
            """\
            import os
            import sys

            def greet(name: str) -> str:
                return f"Hello, {name}"
            """,
        )
        result = analyze_file(p)
        assert result.error_count == 0

    def test_detects_undefined_import(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "bad_import.py",
            "import totally_nonexistent_module_xyz\n",
        )
        result = analyze_file(p)
        assert result.error_count >= 1
        categories = [i.category for i in result.issues]
        assert "undefined_import" in categories

    def test_detects_hallucinated_from_import(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "bad_from.py",
            "from os.path import nonexistent_function_abc\n",
        )
        result = analyze_file(p)
        errors = [i for i in result.issues if i.category == "hallucinated_attribute"]
        assert len(errors) >= 1

    def test_valid_from_import(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "good_from.py",
            "from os.path import join, exists\n",
        )
        result = analyze_file(p)
        attr_errors = [i for i in result.issues if i.category == "hallucinated_attribute"]
        assert len(attr_errors) == 0

    def test_missing_return_warning(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "no_return.py",
            """\
            def compute(x: int) -> int:
                y = x + 1
            """,
        )
        result = analyze_file(p)
        warn_cats = [i.category for i in result.issues if i.severity == "warning"]
        assert "missing_return" in warn_cats

    def test_syntax_error_handled(self, tmp_path: Path):
        p = write_tmp(tmp_path, "syntax.py", "def broken(\n")
        result = analyze_file(p)
        assert result.error_count >= 1

    def test_nodes_visited_nonzero(self, tmp_path: Path):
        p = write_tmp(tmp_path, "nodes.py", "x = 1 + 2\n")
        result = analyze_file(p)
        assert result.nodes_visited > 0

    def test_imports_validated_count(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "imports.py",
            """\
            import os
            import sys
            from pathlib import Path
            """,
        )
        result = analyze_file(p)
        assert result.imports_validated == 3


# ---------------------------------------------------------------------------
# Security Checker Tests
# ---------------------------------------------------------------------------


class TestSecurityChecker:
    def test_detects_hardcoded_password(self, tmp_path: Path):
        p = write_tmp(tmp_path, "secret.py", "password = 'SuperSecret123'\n")
        result = scan_file(p)
        assert result.critical_count >= 1
        assert any(i.category == "hardcoded_secret" for i in result.issues)

    def test_detects_sql_injection_percent(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "sql.py",
            """\
            user = input()
            cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
            """,
        )
        result = scan_file(p)
        assert any(i.category == "sql_injection" for i in result.issues)

    def test_detects_shell_true(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "cmd.py",
            """\
            import subprocess
            subprocess.run(["ls", "-la"], shell=True)
            """,
        )
        result = scan_file(p)
        assert any(i.category == "command_injection" for i in result.issues)

    def test_detects_pickle_loads(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "pickle_bad.py",
            """\
            import pickle
            data = pickle.loads(user_input)
            """,
        )
        result = scan_file(p)
        assert any(i.category == "insecure_deserialization" for i in result.issues)

    def test_detects_yaml_load_no_loader(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "yaml_bad.py",
            """\
            import yaml
            data = yaml.load(stream)
            """,
        )
        result = scan_file(p)
        assert any(i.category == "insecure_deserialization" for i in result.issues)

    def test_yaml_safe_load_passes(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "yaml_good.py",
            """\
            import yaml
            data = yaml.safe_load(stream)
            """,
        )
        result = scan_file(p)
        deser_issues = [i for i in result.issues if i.category == "insecure_deserialization"]
        assert len(deser_issues) == 0

    def test_clean_file_passes(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "clean.py",
            """\
            import os

            def get_db_url() -> str:
                return os.environ["DATABASE_URL"]
            """,
        )
        result = scan_file(p)
        assert result.passed()

    def test_api_key_env_no_flag(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "env_key.py",
            """\
            import os
            api_key = os.getenv("OPENAI_API_KEY")
            """,
        )
        result = scan_file(p)
        secret_issues = [i for i in result.issues if i.category == "hardcoded_secret"]
        assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# Review Checklist Tests
# ---------------------------------------------------------------------------


class TestReviewChecklist:
    def test_well_annotated_function_passes(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "annotated.py",
            '''\
            def add(x: int, y: int) -> int:
                """Add two integers."""
                return x + y
            ''',
        )
        report = run_checklist(p)
        api_fails = [
            r for r in report.results
            if r.category == "API Contract" and r.status == CheckStatus.FAIL
        ]
        assert len(api_fails) == 0

    def test_none_default_without_guard_warns(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "none_param.py",
            """\
            def process(data=None):
                return data.upper()
            """,
        )
        report = run_checklist(p)
        edge_warns = [
            r for r in report.results
            if r.category == "Edge Cases" and r.status == CheckStatus.WARN
        ]
        assert len(edge_warns) >= 1

    def test_bare_except_pass_fails(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "bare_except.py",
            """\
            try:
                x = int(input())
            except:
                pass
            """,
        )
        report = run_checklist(p)
        fails = [r for r in report.results if r.status == CheckStatus.FAIL]
        assert len(fails) >= 1

    def test_n_plus_one_detected(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "nplusone.py",
            """\
            for user_id in user_ids:
                user = db.query(User).filter(User.id == user_id).first()
            """,
        )
        report = run_checklist(p)
        perf_warns = [
            r for r in report.results
            if r.category == "Performance" and r.status == CheckStatus.WARN
        ]
        assert len(perf_warns) >= 1

    def test_generator_instead_of_list_comp_warns(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "alloc.py",
            """\
            total = sum([x * 2 for x in range(100)])
            """,
        )
        report = run_checklist(p)
        alloc_warns = [
            r for r in report.results
            if "allocation" in r.name.lower() and r.status == CheckStatus.WARN
        ]
        assert len(alloc_warns) >= 1

    def test_report_render_returns_string(self, tmp_path: Path):
        p = write_tmp(tmp_path, "render.py", "x = 1\n")
        report = run_checklist(p)
        rendered = report.render()
        assert isinstance(rendered, str)
        assert "Checklist" in rendered


# ---------------------------------------------------------------------------
# Pipeline Integration Tests
# ---------------------------------------------------------------------------


class TestPipeline:
    def test_clean_file_passes_pipeline(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "clean.py",
            '''\
            import os
            from pathlib import Path

            def read_config(path: Path) -> dict:
                """Load a JSON config from disk."""
                import json
                with open(path) as f:
                    return json.load(f)
            ''',
        )
        result = review_file(p)
        assert isinstance(result, PipelineResult)
        # No security critical issues
        assert result.security.critical_count == 0

    def test_insecure_file_fails_pipeline(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "insecure.py",
            """\
            secret_key = 'hardcoded_secret_key_123456'

            def query(cursor, user):
                cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
            """,
        )
        result = review_file(p)
        assert not result.passed

    def test_pipeline_result_json_serializable(self, tmp_path: Path):
        import json

        p = write_tmp(tmp_path, "simple.py", "x = 1\n")
        result = review_file(p)
        data = result.to_json()
        serialized = json.dumps(data)
        assert isinstance(serialized, str)

    def test_pipeline_duration_positive(self, tmp_path: Path):
        p = write_tmp(tmp_path, "dur.py", "y = 2 + 2\n")
        result = review_file(p)
        assert result.duration_ms > 0

    def test_review_record_fields(self, tmp_path: Path):
        p = write_tmp(tmp_path, "rec.py", "z = 3\n")
        result = review_file(p)
        record = result.to_record()
        assert record.file == str(p)
        assert isinstance(record.overall_passed, bool)
        assert isinstance(record.timestamp, str)


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_file(self, tmp_path: Path):
        p = write_tmp(tmp_path, "empty.py", "")
        ast_result = analyze_file(p)
        sec_result = scan_file(p)
        assert ast_result.error_count == 0
        assert sec_result.critical_count == 0

    def test_file_with_only_comments(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "comments.py",
            """\
            # This file has only comments
            # and no executable code
            """,
        )
        result = analyze_file(p)
        assert result.error_count == 0

    def test_deeply_nested_function(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "nested.py",
            """\
            def outer():
                def inner():
                    def innermost():
                        return 42
                    return innermost()
                return inner()
            """,
        )
        result = analyze_file(p)
        # Should handle nesting without crashing
        assert isinstance(result, AnalysisResult)

    def test_nonexistent_file(self, tmp_path: Path):
        p = tmp_path / "does_not_exist.py"
        result = analyze_file(p)
        assert result.error_count >= 1

    def test_unicode_source(self, tmp_path: Path):
        p = write_tmp(
            tmp_path,
            "unicode.py",
            '# -*- coding: utf-8 -*-\nname = "日本語テスト"\n',
        )
        result = analyze_file(p)
        assert isinstance(result, AnalysisResult)
