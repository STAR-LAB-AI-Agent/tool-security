"""配置工具与配置执行器测试（M2/M5）。"""
import json
import tempfile
import unittest
from pathlib import Path

from agent.agent import ToolSecurityAgent
from agent.audit import AuditLogger
from agent.config_tools import (
    CONFIG_REGISTRY,
    ConfigExecutor,
    describe_config_tools_for_llm,
    get_config_tool,
)
from agent.directory_policy import DirectoryPolicy
from agent.policy_store import Policy, load_policy
from agent.security import AgentConfig, RiskLevel


def _make_executor(
    tmp: Path, policy=None, input_fn=None, policy_path=None, **config_kwargs
) -> ConfigExecutor:
    policy = policy or Policy()
    audit = AuditLogger(tmp / "audit.jsonl")
    config = AgentConfig(**config_kwargs)
    return ConfigExecutor(
        policy, audit, config, "sess-test",
        input_fn=input_fn, policy_path=policy_path,
    )


def _queue(answers):
    """按顺序吐出预置回答的 input_fn，用于模拟多轮交互。"""
    it = iter(answers)
    def fn(prompt=""):
        return next(it)
    return fn


class TestConfigRegistry(unittest.TestCase):
    def test_registered_config_tools(self):
        self.assertEqual(
            set(CONFIG_REGISTRY),
            {
                "configure_tools", "set_tool_policy", "set_max_risk",
                "add_directory_whitelist", "add_command_whitelist",
                "assess_tool", "assess_builtin_tools",
            },
        )
        self.assertIsNotNone(get_config_tool("set_max_risk"))
        self.assertIsNone(get_config_tool("not_a_config_tool"))

    def test_describe_contains_tool(self):
        desc = describe_config_tools_for_llm()
        self.assertIn("set_max_risk", desc)


class TestConfigExecutor(unittest.TestCase):
    def test_set_max_risk(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("set_max_risk", {"risk": "low"})
            self.assertTrue(result.ok)
            self.assertEqual(ex.policy.max_risk, RiskLevel.LOW)

    def test_set_tool_policy(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("set_tool_policy", {"tool": "delete_file", "allowed": False})
            self.assertTrue(result.ok)
            self.assertFalse(ex.policy.tool_policies["delete_file"].allowed)

    def test_add_directory_whitelist(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("add_directory_whitelist", {"path": "data"})
            self.assertTrue(result.ok)
            self.assertIn("data", ex.policy.directory_whitelist)

    def test_add_command_whitelist(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("add_command_whitelist", {"command": "ls"})
            self.assertTrue(result.ok)
            self.assertIn("ls", ex.policy.command_whitelist)

    def test_force_confirmation_ignores_auto_approve(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), auto_approve=True, confirm_fn=lambda tool, keys: False)
            result = ex.execute("set_max_risk", {"risk": "low"})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "denied")

    def test_unregistered_config_tool_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("not_a_config_tool", {})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")

    def test_filter_drops_unknown_keys(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("set_max_risk", {"risk": "low", "extra": "x"})
            self.assertTrue(result.ok)
            self.assertEqual(ex.policy.max_risk, RiskLevel.LOW)

    def test_invalid_risk_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d), confirm_fn=lambda tool, keys: True)
            result = ex.execute("set_max_risk", {"risk": "critical"})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")


class TestAgentConfigRouting(unittest.TestCase):
    def test_keyword_routes_to_configure_tools(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            agent = ToolSecurityAgent(
                DirectoryPolicy([ws]),
                AuditLogger(ws / "audit.jsonl"),
                AgentConfig(confirm_fn=lambda tool, keys: True),
                input_fn=_queue([""] * 5 + ["y"]),
            )
            result = agent.run("我希望对现有工具做安全控制")
            self.assertTrue(result.ok)
            self.assertIn("max_risk", result.data)


class TestConfigureToolsWizard(unittest.TestCase):
    def test_wizard_updates_tool_policies(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # 逐项：禁止 list_dir、允许 read_file、其余跳过、最终确认。
            answers = ["n", "y", "", "", "", "", "y"]
            ex = _make_executor(
                ws, confirm_fn=lambda tool, keys: True, input_fn=_queue(answers)
            )
            result = ex.execute("configure_tools", {})
            self.assertTrue(result.ok)
            self.assertFalse(ex.policy.tool_policies["list_dir"].allowed)
            self.assertTrue(ex.policy.tool_policies["read_file"].allowed)

    def test_wizard_cancel_aborts_without_changes(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            ex = _make_executor(
                ws, confirm_fn=lambda tool, keys: True,
                input_fn=_queue([""] * 5 + ["n"]),
            )
            result = ex.execute("configure_tools", {})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertIn("取消", result.error)
            self.assertEqual(ex.policy.tool_policies, {})

    def test_wizard_persists_policy_when_path_set(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            policy_path = ws / "policy.json"
            ex = _make_executor(
                ws, confirm_fn=lambda tool, keys: True,
                input_fn=_queue([""] * 5 + ["y"]), policy_path=policy_path,
            )
            result = ex.execute("configure_tools", {})
            self.assertTrue(result.ok)
            self.assertTrue(policy_path.is_file())
            self.assertEqual(load_policy(policy_path).max_risk, ex.policy.max_risk)


class TestConfigAudit(unittest.TestCase):
    def test_config_change_audit_records_detail(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            ex = _make_executor(ws, confirm_fn=lambda tool, keys: True)
            result = ex.execute("set_max_risk", {"risk": "low"})
            self.assertTrue(result.ok)
            lines = (ws / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
            entry = json.loads(lines[-1])
            self.assertEqual(entry["decision"], "allowed")
            self.assertEqual(entry["detail"], {"max_risk": "low"})

    def test_force_confirmation_does_not_modify_policy(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            ex = _make_executor(ws, auto_approve=True, confirm_fn=lambda tool, keys: False)
            result = ex.execute("set_tool_policy", {"tool": "delete_file", "allowed": True})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "denied")
            self.assertNotIn("delete_file", ex.policy.tool_policies)

    def test_agent_cannot_bypass_config_confirmation(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            agent = ToolSecurityAgent(
                DirectoryPolicy([ws]),
                AuditLogger(ws / "audit.jsonl"),
                AgentConfig(auto_approve=True, confirm_fn=lambda tool, keys: False),
            )
            result = agent.run("把最大风险设为 low")
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "denied")
            self.assertEqual(agent.policy.max_risk, RiskLevel.HIGH)


if __name__ == "__main__":
    unittest.main()
