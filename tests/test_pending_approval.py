"""显式批准机制测试：待批准请求（两段式）。"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.audit import AuditLogger
from core.config_tools import ConfigExecutor
from core.pending_approval import PendingStore
from core.policy_store import Policy
from core.security import AgentConfig, RiskLevel


def _make_executor(tmp: Path, pending_store=None, policy=None) -> ConfigExecutor:
    return ConfigExecutor(
        policy or Policy(),
        AuditLogger(tmp / "audit.jsonl"),
        AgentConfig(),
        "sess-test",
        pending_store=pending_store,
    )


class TestPendingStore(unittest.TestCase):
    def test_create_approve_consume(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"})
            self.assertEqual(req.status, "pending")
            self.assertTrue(store.load(req.id).params == {"risk": "low"})

            ok, _ = store.approve(req.id)
            self.assertTrue(ok)
            self.assertEqual(store.load(req.id).status, "approved")

            ok, _ = store.consume(req.id, "set_max_risk", {"risk": "low"})
            self.assertTrue(ok)
            self.assertIsNone(store.load(req.id))  # 一次性消费后删除

    def test_consume_unapproved_denied(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"})
            ok, msg = store.consume(req.id, "set_max_risk", {"risk": "low"})
            self.assertFalse(ok)
            self.assertIn("尚未被人类批准", msg)
            self.assertEqual(store.load(req.id).status, "pending")

    def test_consume_param_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"})
            store.approve(req.id)
            ok, msg = store.consume(req.id, "set_max_risk", {"risk": "medium"})
            self.assertFalse(ok)
            self.assertIn("参数不一致", msg)
            self.assertEqual(store.load(req.id).status, "approved")  # 未消费

    def test_consume_tool_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"})
            store.approve(req.id)
            ok, msg = store.consume(req.id, "set_tool_policy", {"risk": "low"})
            self.assertFalse(ok)
            self.assertIn("工具不匹配", msg)

    def test_deny_removes(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"})
            self.assertTrue(store.deny(req.id))
            self.assertIsNone(store.load(req.id))

    def test_expired_cannot_approve(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            req = store.create("set_max_risk", {"risk": "low"}, ttl=-1)  # 立即过期
            ok, _ = store.approve(req.id)
            self.assertFalse(ok)
            self.assertIsNone(store.load(req.id))  # 过期项被清理

    def test_list_pending_skips_expired(self):
        with tempfile.TemporaryDirectory() as d:
            store = PendingStore(Path(d))
            store.create("set_max_risk", {"risk": "low"})
            store.create("set_max_risk", {"risk": "medium"}, ttl=-1)
            self.assertEqual(len(store.list_pending()), 1)


class TestConfigExecutorPending(unittest.TestCase):
    def test_non_interactive_creates_pending_without_change(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            store = PendingStore(ws / "pending")
            ex = _make_executor(ws, pending_store=store)
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("set_max_risk", {"risk": "low"})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "pending")
            self.assertEqual(ex.policy.max_risk, RiskLevel.HIGH)  # 未修改
            rid = result.data["request_id"]
            self.assertIn("approve_cmd", result.data)
            self.assertEqual(store.load(rid).status, "pending")

    def test_pending_full_flow(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            store = PendingStore(ws / "pending")
            ex = _make_executor(ws, pending_store=store)
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("set_max_risk", {"risk": "low"})
            rid = result.data["request_id"]

            ok, _ = store.approve(rid)
            self.assertTrue(ok)

            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result2 = ex.execute("set_max_risk", {"risk": "low"}, pending_id=rid)
            self.assertTrue(result2.ok)
            self.assertEqual(ex.policy.max_risk, RiskLevel.LOW)
            self.assertIsNone(store.load(rid))  # 一次性消费

    def test_pending_replay_param_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            store = PendingStore(ws / "pending")
            ex = _make_executor(ws, pending_store=store)
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("set_max_risk", {"risk": "low"})
            rid = result.data["request_id"]
            store.approve(rid)

            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result2 = ex.execute("set_max_risk", {"risk": "medium"}, pending_id=rid)
            self.assertFalse(result2.ok)
            self.assertEqual(result2.decision, "denied")
            self.assertEqual(ex.policy.max_risk, RiskLevel.HIGH)  # 未修改

    def test_pending_replay_unapproved_denied(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            store = PendingStore(ws / "pending")
            ex = _make_executor(ws, pending_store=store)
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("set_max_risk", {"risk": "low"})
            rid = result.data["request_id"]

            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result2 = ex.execute("set_max_risk", {"risk": "low"}, pending_id=rid)
            self.assertFalse(result2.ok)
            self.assertEqual(result2.decision, "denied")
            self.assertEqual(ex.policy.max_risk, RiskLevel.HIGH)

    def test_pending_id_without_store_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            ex = _make_executor(Path(d))  # pending_store=None
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("set_max_risk", {"risk": "low"}, pending_id="abc")
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")

    def test_configure_tools_not_pending_eligible(self):
        # configure_tools 是多轮交互向导，非交互下仍应安全拒绝而非生成待批准请求。
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            store = PendingStore(ws / "pending")
            ex = _make_executor(ws, pending_store=store)
            with mock.patch("core.config_tools._is_interactive_terminal", return_value=False):
                result = ex.execute("configure_tools", {})
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertEqual(store.list_pending(), [])


if __name__ == "__main__":
    unittest.main()
