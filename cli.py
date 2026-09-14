"""AI Agent 工具安全控制 —— 独立 CLI 入口。

自然语言模式（独立使用 / 离线兜底）：
    python cli.py "读取 sample.txt"
    python cli.py --list-tools
    python cli.py --max-risk low "删除 a.txt"     # 最小权限拦截

结构化模式（供 nanobot 等 Agent Runtime 以 Skill + Script 方式调用）：
    python cli.py --tool read_file --param path=sample.txt
    python cli.py --tool write_file --params '{"path": "note.txt", "content": "hi"}'
    python cli.py --tool delete_file --param path=a.txt --auto-approve
    python cli.py --tool assess_builtin_tools
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agent import ToolSecurityAgent
from core.audit import AuditLogger
from core.directory_policy import DirectoryPolicy
from core.llm_router import LLMRouter
from core.security import AgentConfig, RiskLevel, SecurityError
from core.settings import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE = PROJECT_ROOT / "data"          # 目录白名单允许的根目录
AUDIT_LOG = PROJECT_ROOT / "logs" / "audit.jsonl"  # 审计日志（位于白名单之外）
POLICY_PATH = PROJECT_ROOT / "config" / "policy.json"  # 安全策略（配置期写入）


def parse_risk(s: str) -> RiskLevel:
    return {"low": RiskLevel.LOW, "medium": RiskLevel.MEDIUM, "high": RiskLevel.HIGH}[s.lower()]


def _parse_params(params_json: Optional[str], param_kvs: List[str]) -> Dict[str, Any]:
    """解析结构化调用的参数：--params 给 JSON 对象，--param 给 key=value（可重复）。"""
    params: Dict[str, Any] = {}
    if params_json:
        try:
            loaded = json.loads(params_json)
        except json.JSONDecodeError as e:
            raise SystemExit(f"[参数错误] --params 不是合法 JSON：{e}") from None
        if not isinstance(loaded, dict):
            raise SystemExit("[参数错误] --params 必须是 JSON 对象（键值对）")
        params.update(loaded)
    for kv in param_kvs:
        if "=" not in kv:
            raise SystemExit(f"[参数错误] --param 需为 key=value 形式，收到：{kv}")
        key, value = kv.split("=", 1)
        params[key.strip()] = value.strip()
    return params


def build_agent(max_risk: RiskLevel, auto_approve: bool, use_llm: bool = True) -> ToolSecurityAgent:
    policy = DirectoryPolicy([WORKSPACE])
    audit = AuditLogger(AUDIT_LOG)
    llm_router = None
    if use_llm:
        env = load_dotenv(PROJECT_ROOT)  # 向上查找 .env（支持父目录共享）
        llm_router = LLMRouter.from_env(env)
        if not llm_router.available:
            llm_router = None  # 未配置 key 时自动回退到关键词路由
    return ToolSecurityAgent(
        policy, audit,
        AgentConfig(max_risk=max_risk, auto_approve=auto_approve),
        llm_router=llm_router,
        policy_path=POLICY_PATH,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AI Agent 工具安全控制（题目 26 雏形）")
    parser.add_argument("intent", nargs="*", help="自然语言指令（与 --tool 二选一）")
    parser.add_argument("--tool", help="结构化调用：工具名（与自然语言 intent 二选一）")
    parser.add_argument("--params", help="结构化调用：JSON 对象参数，如 '{\"path\":\"a.txt\"}'")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE",
                        help="结构化调用：key=value 参数，可重复")
    parser.add_argument("--max-risk", default="high", choices=["low", "medium", "high"],
                        help="会话最小权限：允许调用的最高风险等级")
    parser.add_argument("--auto-approve", action="store_true", help="自动批准危险操作（演示用）")
    parser.add_argument("--list-tools", action="store_true", help="列出当前会话可用工具")
    parser.add_argument("--no-llm", action="store_true", help="禁用 LLM 路由，强制使用关键词路由")
    args = parser.parse_args(argv)

    # 结构化调用不需要 LLM 路由，也不加载 .env。
    use_llm = not args.no_llm and not args.tool
    agent = build_agent(parse_risk(args.max_risk), args.auto_approve, use_llm=use_llm)
    route_mode = "LLM" if (agent.llm_router and agent.llm_router.available) else "关键词"

    if args.list_tools:
        print(f"[会话 {agent.session_id}] 路由模式={route_mode}，可用工具（max_risk={args.max_risk}）：")
        print(agent.describe())
        return 0

    if args.tool:
        params = _parse_params(args.params, args.param)
        print(f"[会话 {agent.session_id}] 结构化调用，工具={args.tool}，参数={params}")
        try:
            result = agent.run_tool(args.tool, params)
        except SecurityError as e:
            print(f"[拦截] {e}")
            return 2
        if result.ok:
            print("[成功]", result.data)
            return 0
        print(f"[{result.decision}] {result.error}")
        return 3

    intent = " ".join(args.intent)
    if not intent:
        parser.print_help()
        return 1

    print(f"[会话 {agent.session_id}] 路由模式={route_mode}，意图：{intent}")
    try:
        result = agent.run(intent)
    except SecurityError as e:
        print(f"[拦截] {e}")
        return 2

    if result.ok:
        print("[成功]", result.data)
        return 0
    print(f"[{result.decision}] {result.error}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
