"""运行期加载安全策略（M4）：policy.json 覆盖代码内默认策略。"""
import tempfile
import unittest
from pathlib import Path

from agent.audit import AuditLogger
from agent.directory_policy import DirectoryPolicy
from agent.gateway import ToolGateway
from agent.policy_store import Policy, ToolPolicy
from agent.security import AgentConfig, RiskLevel


def _make_gateway(tmp: Path, policy=None, **config_kwargs) -> ToolGateway:
    audit = AuditLogger(tmp / "audit.jsonl")
    config = AgentConfig(**config_kwargs)
    return ToolGateway(DirectoryPolicy([tmp]), audit, config, policy=policy)


class TestGatewayLoadsPolicy(unittest.TestCase):
    def test_tool_policy_disallows_tool(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            policy = Policy(tool_policies={"delete_file": ToolPolicy(allowed=False)})
            gw = _make_gateway(ws, policy, confirm_fn=lambda t, k: True)
            result = gw.execute("delete_file", {"path": "a.txt"})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertIn("工具策略", result.error)

    def test_tool_policy_risk_override_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            policy = Policy(tool_policies={"read_file": ToolPolicy(risk=RiskLevel.HIGH)})
            gw = _make_gateway(ws, policy, max_risk=RiskLevel.LOW)
            result = gw.execute("read_file", {"path": "a.txt"})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertIn("最小权限", result.error)

    def test_command_whitelist_override(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            policy = Policy(command_whitelist=["echo"])
            gw = _make_gateway(ws, policy, auto_approve=True)
            blocked = gw.execute("run_command", {"command": "ls"})
            self.assertFalse(blocked.ok)
            self.assertIn("命令白名单", blocked.error)
            allowed = gw.execute("run_command", {"command": "echo hi"})
            self.assertTrue(allowed.ok)

    def test_directory_whitelist_append_absolute(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ws = root / "ws"
            ws.mkdir()
            extra = root / "extra"
            extra.mkdir()
            (extra / "note.txt").write_text("secret", encoding="utf-8")
            policy = Policy(directory_whitelist=[str(extra)])
            gw = ToolGateway(
                DirectoryPolicy([ws]),
                AuditLogger(root / "audit.jsonl"),
                AgentConfig(),
                policy=policy,
            )
            result = gw.execute("read_file", {"path": str(extra / "note.txt")})
            self.assertTrue(result.ok)
            self.assertIn("secret", result.data["content"])

    def test_confirm_required_forces_low_risk_tool(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            policy = Policy(confirm_required=["list_dir"])
            gw = _make_gateway(ws, policy, confirm_fn=lambda t, k: False)
            result = gw.execute("list_dir", {"path": "."})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "denied")


if __name__ == "__main__":
    unittest.main()
