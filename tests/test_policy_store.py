"""policy_store 数据结构与持久化测试（M1）。"""
import json
import tempfile
import unittest
from pathlib import Path

from agent.policy_store import Policy, ToolPolicy, load_policy, save_policy
from agent.security import RiskLevel


class TestPolicyStore(unittest.TestCase):
    def test_roundtrip(self):
        policy = Policy(
            max_risk=RiskLevel.MEDIUM,
            auto_approve=False,
            tool_policies={
                "read_file": ToolPolicy(allowed=True, risk=RiskLevel.LOW),
                "delete_file": ToolPolicy(allowed=False),
            },
            directory_whitelist=["data"],
            command_whitelist=["ls", "echo"],
            confirm_required=["write_file"],
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config" / "policy.json"
            save_policy(policy, path)
            loaded = load_policy(path)
        self.assertEqual(loaded.max_risk, RiskLevel.MEDIUM)
        self.assertFalse(loaded.auto_approve)
        self.assertEqual(loaded.directory_whitelist, ["data"])
        self.assertEqual(loaded.command_whitelist, ["ls", "echo"])
        self.assertEqual(loaded.confirm_required, ["write_file"])
        self.assertTrue(loaded.tool_policies["read_file"].allowed)
        self.assertEqual(loaded.tool_policies["read_file"].risk, RiskLevel.LOW)
        self.assertFalse(loaded.tool_policies["delete_file"].allowed)

    def test_load_missing_returns_default(self):
        with tempfile.TemporaryDirectory() as d:
            policy = load_policy(Path(d) / "not_exists.json")
        self.assertEqual(policy.max_risk, RiskLevel.HIGH)
        self.assertEqual(policy.tool_policies, {})
        self.assertEqual(policy.directory_whitelist, [])

    def test_from_dict_full(self):
        data = {
            "version": 1,
            "max_risk": "low",
            "auto_approve": True,
            "tool_policies": {"read_file": {"allowed": True, "risk": "low"}},
            "directory_whitelist": ["data"],
            "command_whitelist": ["ls"],
            "confirm_required": ["delete_file"],
        }
        policy = Policy.from_dict(data)
        self.assertEqual(policy.max_risk, RiskLevel.LOW)
        self.assertTrue(policy.auto_approve)
        self.assertEqual(policy.tool_policies["read_file"].risk, RiskLevel.LOW)

    def test_tool_policy_risk_none(self):
        tp = ToolPolicy.from_dict({"allowed": True, "risk": None})
        self.assertTrue(tp.allowed)
        self.assertIsNone(tp.risk)

    def test_invalid_risk_raises(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"max_risk": "critical"})

    def test_save_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "a" / "b" / "policy.json"
            save_policy(Policy(), path)
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["max_risk"], "high")


if __name__ == "__main__":
    unittest.main()
