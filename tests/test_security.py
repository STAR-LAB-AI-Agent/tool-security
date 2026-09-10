"""题目 26「AI Agent 工具安全控制」测试用例。"""
import json
import tempfile
import unittest
from pathlib import Path

from agent.agent import ToolSecurityAgent
from agent.audit import AuditLogger
from agent.directory_policy import DirectoryPolicy
from agent.gateway import ToolGateway
from agent.llm_router import LLMRouter
from agent.policy_store import Policy
from agent.registry import TOOL_REGISTRY, describe_tools, get_tool, require_tool
from agent.security import AgentConfig, RiskLevel, SecurityError


def _make_agent(workspace: Path, audit_log: Path, policy=None, **config_kwargs):
    directory_policy = DirectoryPolicy([workspace])
    audit = AuditLogger(audit_log)
    config = AgentConfig(**config_kwargs)
    return ToolSecurityAgent(directory_policy, audit, config, policy=policy)


class TestToolWhitelist(unittest.TestCase):
    def test_registered_tool_available(self):
        self.assertIsNotNone(get_tool("read_file"))
        self.assertEqual(set(TOOL_REGISTRY), {
            "list_dir", "read_file", "write_file", "delete_file", "run_command",
        })

    def test_unregistered_tool_blocked(self):
        with self.assertRaises(SecurityError):
            require_tool("rm -rf /")


class TestDirectoryWhitelist(unittest.TestCase):
    def test_outside_path_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            workspace = Path(d) / "ws"
            workspace.mkdir()
            policy = DirectoryPolicy([workspace])
            with self.assertRaises(SecurityError):
                policy.resolve("../etc/passwd")
            with self.assertRaises(SecurityError):
                policy.resolve("/etc/passwd")

    def test_inside_path_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            workspace = Path(d) / "ws"
            workspace.mkdir()
            policy = DirectoryPolicy([workspace])
            p = policy.resolve("a.txt")
            self.assertTrue(str(p).startswith(str(workspace)))


class TestLeastPrivilege(unittest.TestCase):
    def test_high_risk_tool_blocked_in_low_session(self):
        with tempfile.TemporaryDirectory() as d:
            agent = _make_agent(
                Path(d), Path(d) / "audit.jsonl",
                policy=Policy(enabled=True), max_risk=RiskLevel.LOW,
            )
            result = agent.run("删除 a.txt")
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertIn("最小权限", result.error)

    def test_describe_only_exposes_allowed_risk(self):
        desc = describe_tools(RiskLevel.LOW)
        self.assertIn("read_file", desc)
        self.assertNotIn("delete_file", desc)


class TestDangerConfirmation(unittest.TestCase):
    def test_reject_denies_operation(self):
        with tempfile.TemporaryDirectory() as d:
            agent = _make_agent(
                Path(d), Path(d) / "audit.jsonl",
                policy=Policy(enabled=True),
                confirm_fn=lambda tool, keys: False,
            )
            result = agent.run("删除 a.txt")
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "denied")

    def test_approve_allows_operation(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            agent = _make_agent(
                ws, ws / "audit.jsonl",
                confirm_fn=lambda tool, keys: True,
            )
            result = agent.run("删除 a.txt")
            self.assertTrue(result.ok)
            self.assertFalse((ws / "a.txt").exists())


class TestCommandWhitelist(unittest.TestCase):
    def test_dangerous_command_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            agent = _make_agent(
                Path(d), Path(d) / "audit.jsonl",
                policy=Policy(enabled=True),
                auto_approve=True,
            )
            result = agent.run("执行 rm -rf /")
            self.assertFalse(result.ok)
            self.assertIn("命令白名单", result.error)


class TestIntentRouting(unittest.TestCase):
    def test_read_route(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("hello", encoding="utf-8")
            agent = _make_agent(ws, ws / "audit.jsonl")
            result = agent.run("读取 a.txt")
            self.assertTrue(result.ok)
            self.assertIn("hello", result.data["content"])

    def test_list_route(self):
        with tempfile.TemporaryDirectory() as d:
            agent = _make_agent(Path(d), Path(d) / "audit.jsonl")
            result = agent.run("列出目录")
            self.assertTrue(result.ok)


class TestAuditLog(unittest.TestCase):
    def test_audit_written_without_param_values(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            log = ws / "audit.jsonl"
            agent = _make_agent(ws, log, auto_approve=True)
            secret = "SUPER_SECRET_VALUE"
            agent.run(f"写入 note.txt 内容：{secret}")
            self.assertTrue(log.exists())
            lines = log.read_text(encoding="utf-8").strip().splitlines()
            self.assertTrue(lines)
            entry = json.loads(lines[-1])
            self.assertEqual(entry["tool"], "write_file")
            self.assertEqual(set(entry["params_keys"]), {"path", "content"})
            # 审计日志不记录参数值，因此不应包含敏感内容
            self.assertNotIn(secret, json.dumps(entry, ensure_ascii=False))


class TestLLMRouter(unittest.TestCase):
    """LLM 决策解析（不涉及网络，仅测 _parse 的稳健性）。"""

    def test_parse_plain_json(self):
        tool, params = LLMRouter._parse('{"tool": "read_file", "params": {"path": "a.txt"}}')
        self.assertEqual(tool, "read_file")
        self.assertEqual(params, {"path": "a.txt"})

    def test_parse_json_with_surrounding_text(self):
        tool, params = LLMRouter._parse('好的，结果是：{"tool": "delete_file", "params": {"path": "b.txt"}}')
        self.assertEqual(tool, "delete_file")

    def test_parse_null_tool_raises(self):
        with self.assertRaises(SecurityError):
            LLMRouter._parse('{"tool": null, "params": {}}')

    def test_parse_invalid_raises(self):
        with self.assertRaises(SecurityError):
            LLMRouter._parse('这不是 JSON')


class TestPermissionPlanner(unittest.TestCase):
    """最小权限规划：LLM 输出的最小工具集解析（纯函数，不涉及网络）。"""

    def test_parse_tools_list(self):
        tools = LLMRouter._parse_tools('{"tools": ["read_file", "list_dir"]}')
        self.assertEqual(tools, ["read_file", "list_dir"])

    def test_parse_tools_empty(self):
        self.assertEqual(LLMRouter._parse_tools('{"tools": []}'), [])

    def test_parse_tools_invalid_raises(self):
        with self.assertRaises(SecurityError):
            LLMRouter._parse_tools('{"tools": "read_file"}')


class TestTaskLeastPrivilege(unittest.TestCase):
    """任务级最小权限：自动推导的最小工具集之外的工具被拦截。"""

    def test_allowed_tools_blocks_unlisted_tool(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("x", encoding="utf-8")
            agent = _make_agent(ws, ws / "audit.jsonl")
            result = agent.gateway.execute(
                "delete_file", {"path": "a.txt"}, allowed_tools={"read_file"}
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.decision, "blocked")
            self.assertIn("最小权限", result.error)

    def test_allowed_tools_allows_listed_tool(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "a.txt").write_text("hello", encoding="utf-8")
            agent = _make_agent(ws, ws / "audit.jsonl")
            result = agent.gateway.execute(
                "read_file", {"path": "a.txt"}, allowed_tools={"read_file"}
            )
            self.assertTrue(result.ok)
            self.assertIn("hello", result.data["content"])


class TestParamFilter(unittest.TestCase):
    """按工具签名过滤 LLM 可能多给的参数键。"""

    def test_filter_drops_unknown_keys(self):
        tool = get_tool("read_file")
        params = {"path": "a.txt", "max_chars": 100, "extra": "x"}
        filtered = ToolGateway._filter_params(tool, params)
        self.assertEqual(filtered, {"path": "a.txt", "max_chars": 100})


if __name__ == "__main__":
    unittest.main()
