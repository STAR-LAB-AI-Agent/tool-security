"""休眠/激活模式测试：安全控制默认休眠，自然语言触发后进入运行态。"""
import json
import tempfile
import unittest
from pathlib import Path

from agent.agent import ToolSecurityAgent
from agent.audit import AuditLogger
from agent.directory_policy import DirectoryPolicy
from agent.policy_store import Policy, load_policy
from agent.security import AgentConfig, RiskLevel


def _make_agent(ws: Path, policy_path=None, **config_kwargs) -> ToolSecurityAgent:
    return ToolSecurityAgent(
        DirectoryPolicy([ws]),
        AuditLogger(ws / "audit.jsonl"),
        AgentConfig(**config_kwargs),
        policy_path=policy_path,
    )


class TestSleepMode(unittest.TestCase):
    def test_policy_enabled_roundtrip(self):
        self.assertFalse(Policy().enabled)  # 默认休眠
        self.assertTrue(Policy.from_dict(Policy(enabled=True).to_dict()).enabled)

    def test_sleep_mode_bypasses_gateway(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            agent = _make_agent(ws, max_risk=RiskLevel.LOW)
            # 休眠态：即使 max_risk=LOW，delete_file(HIGH) 也旁路执行成功
            result = agent.run("删除 a.txt")
            self.assertTrue(result.ok)
            self.assertEqual(result.decision, "passthrough")
            self.assertFalse((ws / "a.txt").exists())

    def test_sleep_mode_still_audits(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("hello", encoding="utf-8")
            agent = _make_agent(ws)
            result = agent.run("读取 a.txt")
            self.assertTrue(result.ok)
            lines = (ws / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
            entry = json.loads(lines[-1])
            self.assertEqual(entry["decision"], "passthrough")

    def test_activation_persists_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            policy_path = ws / "policy.json"
            agent = _make_agent(ws, policy_path=policy_path, confirm_fn=lambda t, k: True)
            self.assertFalse(agent.policy.enabled)
            result = agent.run("把最大风险设为 low")
            self.assertTrue(result.ok)
            self.assertTrue(agent.policy.enabled)
            self.assertTrue(policy_path.is_file())
            self.assertTrue(load_policy(policy_path).enabled)

    def test_activated_mode_enforces_gateway(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            agent = _make_agent(ws, max_risk=RiskLevel.LOW)
            agent.policy.enabled = True  # 模拟已激活
            result = agent.run("删除 a.txt")
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertTrue((ws / "a.txt").exists())


if __name__ == "__main__":
    unittest.main()
