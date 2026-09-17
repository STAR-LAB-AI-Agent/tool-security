"""接入器（import_tool）与外部工具执行测试。

覆盖：ExternalToolRecord 序列化、subprocess 执行、注册表持久化、
import_external_tool 端到端接入、deny-by-default 闸门、_import_tool 策略写入。
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.audit import AuditLogger
from core.config_tools import _import_tool
from core.directory_policy import DirectoryPolicy
from core.external_tools import (
    ExternalToolRecord,
    load_external_tools,
    record_to_tool,
    register_external_tools_from_disk,
    run_external_tool,
    save_external_tools,
)
from core.gateway import ToolGateway
from core.importer import import_external_tool
from core.policy_store import Policy, ToolPolicy
from core.registry import TOOL_REGISTRY, get_tool, register_tool
from core.security import AgentConfig, ExternalToolSpec, RiskLevel, SecurityError


def _cleanup_registry(*names):
    for name in names:
        TOOL_REGISTRY.pop(name, None)


def _write_echo_cli(workdir: Path) -> None:
    """写一个符合统一 Skill + Script 接口的最小外部 cli.py，回显参数。"""
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "cli.py").write_text(
        "import argparse, json\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    p.add_argument('--tool')\n"
        "    p.add_argument('--param', action='append', default=[])\n"
        "    a = p.parse_args()\n"
        "    params = {}\n"
        "    for kv in a.param:\n"
        "        k, v = kv.split('=', 1)\n"
        "        params[k] = v\n"
        "    print(json.dumps({'tool': a.tool, 'params': params}, ensure_ascii=False))\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )


def _make_fake_project(root: Path, name: str = "demo_counter") -> Path:
    """构造一个带 SKILL.md + cli.py 的假外部 Skill + Script 项目。"""
    proj = root / "src"
    proj.mkdir()
    (proj / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        'description: "A demo counter tool"\n'
        "---\n\n"
        "# Demo\n",
        encoding="utf-8",
    )
    (proj / "cli.py").write_text(
        "import argparse, json\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    p.add_argument('--tool')\n"
        "    p.add_argument('--param', action='append', default=[])\n"
        "    a = p.parse_args()\n"
        "    params = {}\n"
        "    for kv in a.param:\n"
        "        k, v = kv.split('=', 1)\n"
        "        params[k] = v\n"
        "    print(json.dumps({'tool': a.tool, 'params': params}, ensure_ascii=False))\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    return proj


class TestExternalToolRecord(unittest.TestCase):
    def test_roundtrip(self):
        record = ExternalToolRecord(
            name="demo", description="d", workdir="/tmp/demo",
            entry="cli.py", tool_name=None, risk="low",
        )
        restored = ExternalToolRecord.from_dict(record.to_dict())
        self.assertEqual(restored.name, "demo")
        self.assertEqual(restored.workdir, "/tmp/demo")
        self.assertEqual(restored.entry, "cli.py")
        self.assertEqual(restored.risk, "low")
        self.assertFalse(restored.enabled_by_default)

    def test_from_dict_defaults(self):
        restored = ExternalToolRecord.from_dict({"name": "x", "workdir": "/tmp/x"})
        self.assertEqual(restored.entry, "cli.py")
        self.assertEqual(restored.risk, "low")
        self.assertEqual(restored.category, "外部接入")
        self.assertFalse(restored.enabled_by_default)

    def test_record_to_tool_is_external_and_deny_by_default(self):
        record = ExternalToolRecord(name="demo", description="d", workdir="/tmp/demo")
        tool = record_to_tool(record)
        self.assertIsNotNone(tool.external)
        self.assertIsNone(tool.func)
        self.assertFalse(tool.enabled_by_default)
        self.assertEqual(tool.external.workdir, "/tmp/demo")
        self.assertEqual(tool.external.entry, "cli.py")


class TestRunExternalTool(unittest.TestCase):
    def test_runs_and_returns_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_echo_cli(ws)
            spec = ExternalToolSpec(workdir=str(ws), entry="cli.py")
            data = run_external_tool(spec, {"k": "v"})
            self.assertEqual(data["exit_code"], 0)
            self.assertIn('"params": {"k": "v"}', data["stdout"])

    def test_missing_entry_raises(self):
        with tempfile.TemporaryDirectory() as d:
            spec = ExternalToolSpec(workdir=str(Path(d)), entry="nope.py")
            with self.assertRaises(SecurityError):
                run_external_tool(spec, {})


class TestPersistence(unittest.TestCase):
    def test_load_missing_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_external_tools(Path(d) / "nope.json"), [])

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config" / "external_tools.json"
            records = [ExternalToolRecord(name="a", description="d", workdir="/tmp/a")]
            save_external_tools(records, path)
            self.assertTrue(path.is_file())
            loaded = load_external_tools(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].name, "a")

    def test_register_from_disk(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_echo_cli(ws)
            path = ws / "external_tools.json"
            save_external_tools(
                [ExternalToolRecord(name="disk_ext", description="d", workdir=str(ws))],
                path,
            )
            count = register_external_tools_from_disk(path)
            self.assertEqual(count, 1)
            try:
                self.assertIsNotNone(get_tool("disk_ext"))
                self.assertIsNotNone(get_tool("disk_ext").external)
            finally:
                _cleanup_registry("disk_ext")


class TestImportExternalTool(unittest.TestCase):
    def test_import_copies_declares_and_registers(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _make_fake_project(tmp)
            result = import_external_tool(str(src), project_root=tmp)
            try:
                self.assertEqual(result["tool"], "demo_counter")
                self.assertFalse(result["admitted"])
                self.assertEqual(result["risk"], "low")
                # 整包复制到 external/<name>/
                self.assertTrue((tmp / "external" / "demo_counter" / "cli.py").is_file())
                self.assertTrue((tmp / "external" / "demo_counter" / "SKILL.md").is_file())
                # 生成声明 SKILL.md
                self.assertTrue((tmp / "skills" / "demo_counter" / "SKILL.md").is_file())
                # 注册表持久化
                self.assertTrue((tmp / "config" / "external_tools.json").is_file())
                # 运行期动态注册，且 deny-by-default
                tool = get_tool("demo_counter")
                self.assertIsNotNone(tool)
                self.assertIsNone(tool.func)
                self.assertIsNotNone(tool.external)
                self.assertFalse(tool.enabled_by_default)
            finally:
                _cleanup_registry("demo_counter")

    def test_import_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _make_fake_project(tmp)
            import_external_tool(str(src), project_root=tmp)
            try:
                with self.assertRaises(SecurityError):
                    import_external_tool(str(src), project_root=tmp)
            finally:
                _cleanup_registry("demo_counter")

    def test_import_invalid_name_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            src = _make_fake_project(tmp)
            with self.assertRaises(SecurityError):
                import_external_tool(str(src), name="bad name", project_root=tmp)

    def test_import_missing_dir_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SecurityError):
                import_external_tool(str(Path(d) / "nope"), project_root=Path(d))


class TestDenyByDefault(unittest.TestCase):
    def _register_external(self, ws: Path, name: str = "gt_ext") -> None:
        _write_echo_cli(ws)
        register_tool(record_to_tool(
            ExternalToolRecord(name=name, description="d", workdir=str(ws))
        ))

    def test_gateway_blocks_unadmitted_external(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._register_external(ws)
            try:
                gateway = ToolGateway(
                    DirectoryPolicy([ws]), AuditLogger(ws / "audit.jsonl"),
                    AgentConfig(),
                    policy=Policy(),
                )
                result = gateway.execute("gt_ext", {})
                self.assertFalse(result.ok)
                self.assertEqual(result.decision, "blocked")
                self.assertIn("未准入", result.error)
            finally:
                _cleanup_registry("gt_ext")

    def test_gateway_allows_after_admit(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._register_external(ws)
            try:
                policy = Policy(
                    tool_policies={"gt_ext": ToolPolicy(allowed=True, risk=RiskLevel.LOW)}
                )
                gateway = ToolGateway(
                    DirectoryPolicy([ws]), AuditLogger(ws / "audit.jsonl"),
                    AgentConfig(), policy=policy,
                )
                result = gateway.execute("gt_ext", {"k": "v"})
                self.assertTrue(result.ok)
                self.assertEqual(result.decision, "allowed")
                self.assertIn('"k": "v"', result.data["stdout"])
            finally:
                _cleanup_registry("gt_ext")


class TestImportToolPolicyWrite(unittest.TestCase):
    def _fake_result(self, risk="low"):
        return {
            "tool": "ext_x",
            "description": "d",
            "workdir": "/tmp/ext_x",
            "declaration": "/tmp/skills/ext_x/SKILL.md",
            "risk": risk,
            "reasons": ["未发现危险模式（bandit 无命中、无依赖漏洞）"],
            "pip_audit_status": "no_deps",
            "bandit_findings": [],
            "vulnerabilities": [],
            "admitted": False,
        }

    def test_non_interactive_admits_by_suggested_risk(self):
        policy = Policy()
        with mock.patch(
            "core.config_tools.import_external_tool",
            return_value=self._fake_result(),
        ):
            result = _import_tool(policy, "/tmp/fake_project", interactive=False)
        self.assertTrue(result["admitted"])
        self.assertTrue(result["allowed"])
        self.assertEqual(result["confirmed_risk"], "low")
        self.assertTrue(policy.tool_policies["ext_x"].allowed)
        self.assertEqual(policy.tool_policies["ext_x"].risk, RiskLevel.LOW)

    def test_interactive_confirm_keeps_suggested_risk(self):
        policy = Policy()
        with mock.patch(
            "core.config_tools.import_external_tool",
            return_value=self._fake_result(risk="high"),
        ):
            result = _import_tool(
                policy, "/tmp/fake_project",
                input_fn=lambda prompt: "y", interactive=True,
            )
        self.assertEqual(result["confirmed_risk"], "high")
        self.assertTrue(policy.tool_policies["ext_x"].allowed)
        self.assertEqual(policy.tool_policies["ext_x"].risk, RiskLevel.HIGH)

    def test_interactive_modify_risk(self):
        policy = Policy()
        with mock.patch(
            "core.config_tools.import_external_tool",
            return_value=self._fake_result(risk="high"),
        ):
            result = _import_tool(
                policy, "/tmp/fake_project",
                input_fn=lambda prompt: "low", interactive=True,
            )
        self.assertEqual(result["confirmed_risk"], "low")
        self.assertEqual(policy.tool_policies["ext_x"].risk, RiskLevel.LOW)


if __name__ == "__main__":
    unittest.main()
