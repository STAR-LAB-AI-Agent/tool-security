"""AI Agent 工具安全控制 —— 独立 CLI 入口。

用法示例：
    python cli.py "读取 sample.txt"
    python cli.py "列出 ."
    python cli.py --list-tools
    python cli.py --max-risk low "删除 a.txt"     # 最小权限拦截
    python cli.py --auto-approve "写入 note.txt 内容：hello"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent.agent import ToolSecurityAgent
from agent.audit import AuditLogger
from agent.directory_policy import DirectoryPolicy
from agent.llm_router import LLMRouter
from agent.security import AgentConfig, RiskLevel, SecurityError
from agent.settings import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE = PROJECT_ROOT / "data"          # 目录白名单允许的根目录
AUDIT_LOG = PROJECT_ROOT / "logs" / "audit.jsonl"  # 审计日志（位于白名单之外）
POLICY_PATH = PROJECT_ROOT / "config" / "policy.json"  # 安全策略（配置期写入）


def parse_risk(s: str) -> RiskLevel:
    return {"low": RiskLevel.LOW, "medium": RiskLevel.MEDIUM, "high": RiskLevel.HIGH}[s.lower()]


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
    parser.add_argument("intent", nargs="*", help="自然语言指令")
    parser.add_argument("--max-risk", default="high", choices=["low", "medium", "high"],
                        help="会话最小权限：允许调用的最高风险等级")
    parser.add_argument("--auto-approve", action="store_true", help="自动批准危险操作（演示用）")
    parser.add_argument("--list-tools", action="store_true", help="列出当前会话可用工具")
    parser.add_argument("--no-llm", action="store_true", help="禁用 LLM 路由，强制使用关键词路由")
    args = parser.parse_args(argv)

    agent = build_agent(parse_risk(args.max_risk), args.auto_approve, use_llm=not args.no_llm)
    route_mode = "LLM" if (agent.llm_router and agent.llm_router.available) else "关键词"

    if args.list_tools:
        print(f"[会话 {agent.session_id}] 路由模式={route_mode}，可用工具（max_risk={args.max_risk}）：")
        print(agent.describe())
        return 0

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
