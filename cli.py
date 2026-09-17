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

显式批准（两段式，供非交互 Agent 环境修改安全配置）：
    python cli.py --tool set_max_risk --param risk=low       # 1) 生成待批准请求
    python cli.py --approve <request_id>                     # 2) 人类交互批准
    python cli.py --tool set_max_risk --param risk=low --pending-id <request_id>  # 3) 重放执行
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agent import ToolSecurityAgent
from core.audit import AuditLogger
from core.directory_policy import DirectoryPolicy
from core.external_tools import register_external_tools_from_disk
from core.llm_router import LLMRouter
from core.pending_approval import PendingStore
from core.security import AgentConfig, RiskLevel, SecurityError
from core.settings import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE = PROJECT_ROOT / "data"          # 目录白名单允许的根目录
AUDIT_LOG = PROJECT_ROOT / "logs" / "audit.jsonl"  # 审计日志（位于白名单之外）
POLICY_PATH = PROJECT_ROOT / "config" / "policy.json"  # 安全策略（配置期写入）
EXTERNAL_REGISTRY = PROJECT_ROOT / "config" / "external_tools.json"  # 外部工具注册表
PENDING_DIR = PROJECT_ROOT / "logs" / "pending"  # 待批准请求（显式批准，两段式）


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


def _interactive_confirm(tool, params_keys):
    """危险操作确认：交互终端走 input()，非交互（如 nanobot bash 调用）安全拒绝。"""
    if not sys.stdin.isatty():
        raise SecurityError(
            "危险操作需交互确认，但当前为非交互终端；"
            "请在交互终端运行，或使用 --auto-approve（仅演示用）"
        )
    try:
        answer = input(
            f"[危险操作确认] 即将调用工具 '{tool.name}'（风险 {tool.risk.value}），"
            f"参数键 {params_keys}，是否继续？[y/N] "
        ).strip().lower()
    except (EOFError, OSError):
        # stdin 是伪终端但无输入数据（如 PowerShell 子进程）时，input() 会抛 EOFError。
        raise SecurityError(
            "危险操作需交互确认，但当前无法读取交互输入；"
            "请在交互终端运行，或使用 --auto-approve（仅演示用）"
        ) from None
    return answer in ("y", "yes")


def _interactive_input(prompt: str) -> str:
    """配置向导输入：交互终端走 input()，非交互环境安全拒绝并给出替代方案。"""
    if not sys.stdin.isatty():
        raise SecurityError(
            "该配置向导需要交互终端；非交互环境请使用细粒度配置工具"
            "（set_max_risk / set_tool_policy / add_directory_whitelist / add_command_whitelist）"
        )
    try:
        return input(prompt)
    except (EOFError, OSError):
        raise SecurityError(
            "该配置向导需要交互终端；非交互环境请使用细粒度配置工具"
            "（set_max_risk / set_tool_policy / add_directory_whitelist / add_command_whitelist）"
        ) from None


def build_agent(max_risk: RiskLevel, auto_approve: bool, use_llm: bool = True) -> ToolSecurityAgent:
    # 恢复上次接入的外部工具注册（进程每次运行都会重新加载）。
    register_external_tools_from_disk(EXTERNAL_REGISTRY)
    policy = DirectoryPolicy([WORKSPACE])
    audit = AuditLogger(AUDIT_LOG)
    pending_store = PendingStore(PENDING_DIR)
    llm_router = None
    if use_llm:
        env = load_dotenv(PROJECT_ROOT)  # 向上查找 .env（支持父目录共享）
        llm_router = LLMRouter.from_env(env)
        if not llm_router.available:
            llm_router = None  # 未配置 key 时自动回退到关键词路由
    return ToolSecurityAgent(
        policy, audit,
        AgentConfig(max_risk=max_risk, auto_approve=auto_approve, confirm_fn=_interactive_confirm),
        llm_router=llm_router,
        policy_path=POLICY_PATH,
        input_fn=_interactive_input,
        pending_store=pending_store,
    )


def _print_pending(result) -> int:
    """打印待批准提示，返回专属退出码 4。"""
    rid = (result.data or {}).get("request_id")
    cmd = (result.data or {}).get("approve_cmd")
    print(f"[待批准] {result.error}")
    if rid:
        print(f"  请求ID: {rid}")
    if cmd:
        print(f"  人类批准: {cmd}")
    return 4


def _approve_pending(request_id: str) -> int:
    """两段式第 2 步：人类在交互终端审查并批准一条待批准请求。"""
    store = PendingStore(PENDING_DIR)
    req = store.load(request_id)
    if req is None:
        print(f"[错误] 待批准请求 '{request_id}' 不存在或已失效")
        return 3
    if req.status != "pending":
        print(f"[错误] 待批准请求 '{request_id}' 状态为 {req.status}，无需批准")
        return 3
    if req.expires_at < time.time():
        store.deny(request_id)
        print(f"[错误] 待批准请求 '{request_id}' 已过期，请重新发起")
        return 3
    print(f"[待批准请求] {req.id}")
    print(f"  工具: {req.tool}")
    print(f"  参数: {json.dumps(req.params, ensure_ascii=False)}")
    print(f"  过期: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req.expires_at))}")
    try:
        answer = input("是否批准该配置修改？[y/N] ").strip().lower()
    except (EOFError, OSError):
        print("[拦截] 批准操作需交互终端，请在本机交互终端执行")
        return 2
    if answer not in ("y", "yes"):
        store.deny(request_id)
        print("[已拒绝] 已删除该待批准请求，未做任何修改")
        return 0
    ok, msg = store.approve(request_id)
    if not ok:
        print(f"[错误] {msg}")
        return 3
    print(f"[已批准] {msg}。可携带 --pending-id {request_id} 重放执行该配置操作")
    return 0


def _list_pending() -> int:
    store = PendingStore(PENDING_DIR)
    reqs = store.list_pending()
    if not reqs:
        print("[待批准] 当前没有待批准请求")
        return 0
    print("[待批准请求列表]")
    for req in reqs:
        print(f"  - {req.id}  工具={req.tool}  参数={json.dumps(req.params, ensure_ascii=False)}")
    return 0


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
    parser.add_argument("--approve", metavar="REQUEST_ID",
                        help="人类审查并批准一条待批准请求（两段式显式批准）")
    parser.add_argument("--pending-id", metavar="REQUEST_ID",
                        help="重放执行：携带已批准的待批准请求 ID（配合 --tool 使用）")
    parser.add_argument("--list-pending", action="store_true", help="列出当前待批准请求")
    args = parser.parse_args(argv)

    # 两段式显式批准：人类批准与待批准清单查询不依赖 Agent/LLM，直接处理。
    if args.approve:
        return _approve_pending(args.approve)
    if args.list_pending:
        return _list_pending()

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
            result = agent.run_tool(args.tool, params, pending_id=args.pending_id)
        except SecurityError as e:
            print(f"[拦截] {e}")
            return 2
        if result.ok:
            print("[成功]", result.data)
            return 0
        if result.decision == "pending":
            return _print_pending(result)
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
    if result.decision == "pending":
        return _print_pending(result)
    print(f"[{result.decision}] {result.error}")
    return 3


if __name__ == "__main__":
    sys.exit(main())
