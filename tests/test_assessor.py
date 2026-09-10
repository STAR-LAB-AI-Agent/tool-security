"""评估引擎（bandit / pip-audit）测试：风险分级、白名单准入、离线降级、函数级映射。"""
import json
import tempfile
import unittest
from pathlib import Path

from agent.assessor import (
    _parse_pip_audit_json,
    assess_builtin_tools,
    assess_tool_source,
    audit_dependencies,
    run_bandit,
    severity_to_risk,
)
from agent.security import RiskLevel, SecurityError


class TestSeverityMapping(unittest.TestCase):
    def test_severity_to_risk(self):
        self.assertEqual(severity_to_risk("low"), RiskLevel.LOW)
        self.assertEqual(severity_to_risk("medium"), RiskLevel.MEDIUM)
        self.assertEqual(severity_to_risk("high"), RiskLevel.HIGH)
        self.assertEqual(severity_to_risk("HIGH"), RiskLevel.HIGH)


class TestBandit(unittest.TestCase):
    def test_run_bandit_detects_shell_true(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "danger.py"
            p.write_text(
                "import subprocess\n"
                "def run(cmd):\n"
                "    subprocess.run(cmd, shell=True)\n",
                encoding="utf-8",
            )
            findings = run_bandit(p)
            test_ids = {f.test_id for f in findings}
            self.assertIn("B602", test_ids)
            self.assertTrue(any(f.severity == "HIGH" for f in findings))

    def test_run_bandit_missing_source_raises(self):
        with self.assertRaises(SecurityError):
            run_bandit(Path("/nonexistent/tool.py"))


class TestBuiltinAssessment(unittest.TestCase):
    def test_function_level_mapping(self):
        result = assess_builtin_tools()
        # run_command 内含 subprocess shell=True，被 bandit 上调为 high
        self.assertEqual(result["run_command"].risk, RiskLevel.HIGH)
        # read_file 无命中，保持 low
        self.assertEqual(result["read_file"].risk, RiskLevel.LOW)
        # write_file 基础 medium，bandit 无命中，保持 medium（不降级）
        self.assertEqual(result["write_file"].risk, RiskLevel.MEDIUM)
        # 评估只做风险分级，不改变白名单准入
        self.assertTrue(all(tp.allowed for tp in result.values()))


class TestPipAuditParsing(unittest.TestCase):
    def test_parse_with_vulns(self):
        raw = json.dumps({"dependencies": [
            {"name": "demo", "version": "1.0", "vulns": [
                {"id": "PYSEC-1", "aliases": ["CVE-1"], "fix_versions": ["1.1"]}
            ]}
        ]})
        status, vulns = _parse_pip_audit_json(raw)
        self.assertEqual(status, "ok")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].package, "demo")
        self.assertEqual(vulns[0].vuln_id, "PYSEC-1")

    def test_parse_no_vulns(self):
        raw = json.dumps({"dependencies": [{"name": "demo", "version": "1.0", "vulns": []}]})
        status, vulns = _parse_pip_audit_json(raw)
        self.assertEqual(status, "ok")
        self.assertEqual(vulns, [])

    def test_parse_invalid_json_offline(self):
        status, vulns = _parse_pip_audit_json("not json")
        self.assertEqual(status, "skipped_offline")
        self.assertEqual(vulns, [])

    def test_parse_missing_dependencies(self):
        status, vulns = _parse_pip_audit_json("{}")
        self.assertEqual(status, "skipped_offline")
        self.assertEqual(vulns, [])


class TestAuditDependencies(unittest.TestCase):
    def test_no_deps_when_missing(self):
        status, vulns = audit_dependencies(Path("/nonexistent/requirements.txt"))
        self.assertEqual(status, "no_deps")
        self.assertEqual(vulns, [])


class TestAssessToolSource(unittest.TestCase):
    def test_bandit_raises_risk_and_allowed_true_without_deps(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tool.py"
            p.write_text(
                "import subprocess\n"
                "def run(cmd):\n"
                "    subprocess.run(cmd, shell=True)\n",
                encoding="utf-8",
            )
            assessment = assess_tool_source("mytool", p)
            self.assertEqual(assessment.risk, RiskLevel.HIGH)
            self.assertTrue(assessment.allowed)
            self.assertEqual(assessment.pip_audit_status, "no_deps")

    def test_assess_tool_missing_source_raises(self):
        with self.assertRaises(SecurityError):
            assess_tool_source("mytool", Path("/nonexistent/tool.py"))


if __name__ == "__main__":
    unittest.main()
