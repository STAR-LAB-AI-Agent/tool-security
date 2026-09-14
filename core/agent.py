"""自然语言意图路由：智能体只负责「决策」，把决策交给 ToolGateway 安全执行。

职责边界（对应任务书 4.1）：
- 智能体（本模块）：理解用户意图，决定调用哪个工具、参数怎么填。
- ToolGateway（gateway.py）：不信任决策内容，穿过全部安全闸门后才执行。

路由支持两种实现：
- LLM 路由（通过 .env 配置 DeepSeek，LLM 只负责「选工具 + 抽参数」）
- 关键词路由（无网络/未配置时自动回退，保证离线可运行）
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .audit import AuditLogger
from .config_tools import ConfigExecutor, describe_config_tools_for_llm, get_config_tool
from .directory_policy import DirectoryPolicy, RuntimePolicy
from .external_tools import run_external_tool
from .gateway import ToolGateway
from .llm_router import LLMRouter
from .policy_store import Policy, load_policy, save_policy
from .registry import describe_tools, describe_tools_for_llm, get_tool
from .security import AgentConfig, RiskLevel, SecurityError, ToolResult
from .tools import ALL_COMMANDS

# 自然语言意图 → 工具 的路由规则（关键词回退，可整体替换为 LLM / nanobot 决策）。
_INTENT_RULES: List[Tuple[str, re.Pattern]] = [
    ("run_command", re.compile(r"执行|运行|跑一下")),
    ("delete_file", re.compile(r"删除|移除|删掉")),
    ("write_file", re.compile(r"写入|创建|写(文件|入)?")),
    ("read_file", re.compile(r"读取|查看|读(文件)?")),
    ("list_dir", re.compile(r"列出|列举|有哪些|目录里有")),
]

# list_dir 意图中表示「当前目录」的泛化词，不应被当作真实路径参数。
_GENERIC_DIR_WORDS = {"目录", "当前目录", "文件夹", "文件", "内容"}

# 配置类意图（优先于业务意图匹配，关键词兜底；复杂配置应走 LLM 路由）。
_CONFIG_INTENT_RULES: List[Tuple[str, re.Pattern]] = [
    ("assess_builtin_tools", re.compile(r"评估内置工具|内置工具评估|内置工具.*风险|安全自检")),
    ("import_tool", re.compile(r"接入|导入|收编|onboard|import")),
    ("assess_tool", re.compile(r"评估.*(工具|风险|等级)|审计.*工具|扫描.*工具|工具.*(评估|审计|扫描)")),
    ("configure_tools", re.compile(r"安全控制|权限划分|权限设置|权限配置|工具安全")),
    ("set_max_risk", re.compile(r"最小权限|只读权限|风险等级|最大风险")),
    ("add_directory_whitelist", re.compile(r"目录白名单|允许访问.*目录|只允许访问")),
    ("add_command_whitelist", re.compile(r"命令白名单|允许执行.*命令|只允许.*命令")),
    ("confirm_tool_risk", re.compile(r"分级|准入|确认.*(风险|等级)|(分级|风险).*(改成|改为|修改|调整|设为)")),
    ("set_tool_policy", re.compile(r"限制.*(使用|调用)|禁止.*(使用|调用)|允许.*(使用|调用)|禁用|启用")),
]


class ToolSecurityAgent:
    """工具安全控制智能体：理解意图 → 决策 → 交给 ToolGateway 安全执行。"""

    def __init__(
        self,
        directory_policy: DirectoryPolicy,
        audit_logger: AuditLogger,
        config: Optional[AgentConfig] = None,
        llm_router: Optional[LLMRouter] = None,
        policy: Optional[Policy] = None,
        *,
        input_fn: Optional[Callable[[str], str]] = None,
        policy_path: Optional[Union[str, Path]] = None,
    ):
        self.config = config or AgentConfig()
        self.llm_router = llm_router  # 可选：接入真实 LLM 做意图路由
        self.audit = audit_logger
        self.directory_policy = directory_policy
        self.policy_path = policy_path
        self.policy = self._resolve_policy(policy, policy_path)
        self.gateway = ToolGateway(
            directory_policy, audit_logger, self.config, policy=self.policy,
        )
        self.session_id = self.gateway.session_id
        self.config_executor = ConfigExecutor(
            self.policy, audit_logger, self.config, self.session_id,
            input_fn=input_fn, policy_path=policy_path,
        )

    @staticmethod
    def _resolve_policy(
        policy: Optional[Policy], policy_path: Optional[Union[str, Path]]
    ) -> Policy:
        """解析运行期策略：显式传入 > 从 policy.json 加载 > 默认空策略。"""
        if policy is not None:
            return policy
        if policy_path is not None:
            return load_policy(policy_path)
        return Policy()

    # ------------------------------------------------------------------ 决策
    def route(self, intent: str) -> Tuple[str, Dict[str, Any]]:
        """根据自然语言意图决策出（工具名，参数）。

        优先走 LLM 路由（若已配置）；LLM 不可用或失败时回退到关键词路由。
        无论哪条路径，最终工具名都会在 execute 阶段再次经过白名单校验。
        """
        if self.llm_router is not None and self.llm_router.available:
            try:
                tools_desc = (
                    describe_tools_for_llm(self.config.max_risk)
                    + "\n"
                    + describe_config_tools_for_llm()
                )
                tool_name, params = self.llm_router.route(intent, tools_desc)
                self._require_known_tool(tool_name)  # 联合白名单兜底
                return tool_name, params
            except SecurityError:
                pass  # 回退到关键词路由
        return self._keyword_route(intent)

    def _keyword_route(self, intent: str) -> Tuple[str, Dict[str, Any]]:
        for tool_name, pattern in _CONFIG_INTENT_RULES:
            if pattern.search(intent):
                return tool_name, self._extract_config_params(tool_name, intent)
        for tool_name, pattern in _INTENT_RULES:
            if pattern.search(intent):
                return tool_name, self._extract_params(tool_name, intent)
        raise SecurityError("无法理解该意图，请换一种说法（如：读取/写入/删除/列出/执行/权限设置）")

    def _extract_config_params(self, tool_name: str, intent: str) -> Dict[str, Any]:
        """关键词路由下配置工具的简单参数抽取（复杂配置应走 LLM）。"""
        if tool_name == "set_max_risk":
            m = re.search(r"\b(low|medium|high)\b", intent, re.IGNORECASE)
            if m:
                return {"risk": m.group(1).lower()}
        if tool_name == "import_tool":
            # 兜底抽取：引号内路径或「接入/导入」后的文本作为项目路径
            quoted = re.search(r"[\"“']([^\"”']+)[\"”']", intent)
            if quoted:
                return {"path": quoted.group(1)}
            m = re.search(r"(?:接入|导入|收编)\s*[:：]?\s*(.+)", intent)
            if m and m.group(1).strip():
                return {"path": m.group(1).strip()}
        if tool_name == "assess_tool":
            # 兜底抽取：引号内路径作为 source，显式「工具/名称」词后作为 name
            params: Dict[str, Any] = {}
            quoted = re.search(r"[\"“']([^\"”']+)[\"”']", intent)
            if quoted:
                params["source"] = quoted.group(1)
            m = re.search(r"(?:工具|名称|name)\s*[：:]?\s*([\w.-]+)", intent, re.IGNORECASE)
            if m:
                params["name"] = m.group(1).strip()
            return params
        if tool_name == "confirm_tool_risk":
            # 兜底抽取：引号内名称或「工具/名称：」后为 tool，low/medium/high 为 risk
            params: Dict[str, Any] = {}
            quoted = re.search(r"[\"“']([^\"”']+)[\"”']", intent)
            if quoted:
                params["tool"] = quoted.group(1)
            else:
                m = re.search(r"(?:工具|名称|name)\s*[：:]?\s*([\w.-]+)", intent, re.IGNORECASE)
                if m:
                    params["tool"] = m.group(1).strip()
                else:
                    m2 = re.search(r"(?:确认|准入|把|将)\s*[:：]?\s*([\w.-]+)", intent)
                    if m2:
                        params["tool"] = m2.group(1).strip()
                    else:
                        m3 = re.search(r"([\w.-]+)\s*(?:分级|风险|等级)", intent)
                        if m3:
                            params["tool"] = m3.group(1).strip()
            m = re.search(r"\b(low|medium|high)\b", intent, re.IGNORECASE)
            if m:
                params["risk"] = m.group(1).lower()
            return params
        return {}

    def _require_known_tool(self, name: str) -> None:
        """联合白名单兜底：工具必须在业务或配置注册表中。"""
        if get_tool(name) is None and get_config_tool(name) is None:
            raise SecurityError(f"工具白名单拦截：未注册的工具 '{name}' 不允许调用")

    def _extract_params(self, tool_name: str, intent: str) -> Dict[str, Any]:
        if tool_name == "run_command":
            m = re.search(r"(?:执行|运行)\s*(.+)", intent)
            command = (m.group(1) if m else "").strip().strip("“”\"'")
            return {"command": command} if command else {}

        if tool_name == "write_file":
            # 支持「写入 <path> 内容：<content>」或「写入 <path>：<content>」
            m = re.search(r"(?:写入|创建)\s*[:：]?\s*(.+?)\s*内容\s*[:：]\s*(.+)", intent)
            if not m:
                m = re.search(r"(?:写入|创建)\s*[:：]?\s*(\S+)\s*[:：]\s*(.+)", intent)
            if m:
                return {"path": m.group(1).strip(), "content": m.group(2).strip()}
            return {}

        path = self._extract_path(intent)
        if tool_name == "list_dir" and path in _GENERIC_DIR_WORDS:
            path = "."
        return {"path": path} if path else {}

    def _extract_path(self, intent: str) -> Optional[str]:
        quoted = re.search(r"[\"“']([^\"”']+)[\"”']", intent)
        if quoted:
            return quoted.group(1)
        for kw in ("读取", "查看", "写入", "创建", "删除", "移除", "列出", "列举"):
            m = re.search(kw + r"\s*[:：]?\s*(.+)", intent)
            if m and m.group(1).strip():
                return m.group(1).strip()
        return None

    @staticmethod
    def _sanitize_intent(intent: str) -> str:
        """审计用意图脱敏：只保留动作动词，避免把参数值（可能含敏感信息）写入日志。"""
        tokens = intent.strip().split()
        return tokens[0] if tokens else intent

    # ------------------------------------------------------------------ 执行（委托网关）
    def run(self, intent: str) -> Any:
        """理解意图 → 决策 → 交给对应执行器安全执行。

        配置意图走 ConfigExecutor，业务意图走 ToolGateway。
        注：route() 在「意图无法理解」时会抛 SecurityError（由 CLI 捕获），
        其余安全拦截均由执行器内部消化并返回结构化 ToolResult。
        """
        tool_name, params = self.route(intent)
        intent_label = self._sanitize_intent(intent)
        if get_config_tool(tool_name) is not None:
            return self._run_config(tool_name, params, intent_label)
        if not self.policy.enabled:
            # 休眠态：安全控制未激活，业务工具旁路执行（仅审计，不拦截）
            return self._execute_unrestricted(tool_name, params, intent_label)
        allowed_tools = self._derive_allowlist(intent)
        return self.gateway.execute(
            tool_name, params, intent_label=intent_label, allowed_tools=allowed_tools,
        )

    def run_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """结构化调用入口：调用方已选好工具与参数，直接执行，不做意图路由。

        与 run() 的区别：run() 先 route() 把自然语言翻译成（工具名，参数）；
        run_tool() 跳过路由，直接交给对应执行器。适合宿主 agent（如 nanobot）以
        Skill + Script 方式调用：宿主 LLM 已完成「选工具 + 抽参数」，此处不再重复
        理解，也不依赖本项目的 LLM / 关键词路由。
        """
        self._require_known_tool(tool_name)
        if get_config_tool(tool_name) is not None:
            return self._run_config(tool_name, params, tool_name)
        if not self.policy.enabled:
            return self._execute_unrestricted(tool_name, params, tool_name)
        return self.gateway.execute(tool_name, params, intent_label=tool_name)

    def _run_config(self, tool_name: str, params: Dict[str, Any], intent_label: str) -> Any:
        """配置工具走 ConfigExecutor（强制确认 + 审计）；成功后激活安全控制并持久化。"""
        result = self.config_executor.execute(tool_name, params, intent_label=intent_label)
        if result.ok and not self.policy.enabled:
            self.policy.enabled = True
            self._persist_policy()
        return result

    def _persist_policy(self) -> None:
        if self.policy_path is not None:
            save_policy(self.policy, self.policy_path)

    def _execute_unrestricted(
        self, tool_name: str, params: Dict[str, Any], intent_label: str
    ) -> ToolResult:
        """休眠态旁路执行：不经过安全闸门，仅做审计记录（只记录、不拦截）。"""
        tool = get_tool(tool_name)
        if tool is None:
            raise SecurityError(f"未注册的工具 '{tool_name}' 不允许调用")
        params = ToolGateway._filter_params(tool, params)
        params_keys = sorted(params.keys())
        started = time.perf_counter()
        runtime = RuntimePolicy(
            DirectoryPolicy([self.directory_policy.root], unrestricted=True),
            ALL_COMMANDS,
        )
        try:
            if tool.external is not None:
                data = run_external_tool(tool.external, params)
            elif tool.func is not None:
                data = tool.func(runtime, **params)
            else:
                raise SecurityError(f"工具 '{tool_name}' 缺少可执行实现")
            self.audit.record(
                self.session_id, intent_label, tool_name, tool.risk, params_keys,
                "passthrough", "休眠态旁路执行（安全控制未激活）", True,
                (time.perf_counter() - started) * 1000,
            )
            return ToolResult(ok=True, data=data, decision="passthrough")
        except SecurityError as e:
            reason = str(e)
            self.audit.record(
                self.session_id, intent_label, tool_name, tool.risk, params_keys,
                "blocked", reason, False, (time.perf_counter() - started) * 1000, reason,
            )
            return ToolResult(ok=False, error=reason, decision="blocked")
        except Exception as e:  # 兜底，避免旁路执行异常导致智能体失控
            reason = f"执行异常：{e}"
            self.audit.record(
                self.session_id, intent_label, tool_name, tool.risk, params_keys,
                "error", reason, False, (time.perf_counter() - started) * 1000, reason,
            )
            return ToolResult(ok=False, error=reason, decision="error")

    def _derive_allowlist(self, intent: str) -> Optional[Set[str]]:
        """按任务自动推导最小工具集（最小权限的自动化）。

        仅当配置了可用 LLM 时生效；推导失败或未配置时返回 None（回退到 max_risk 分级）。
        推导结果叠加两道兜底：工具白名单（必须已注册）+ max_risk（不越权）。
        """
        if self.llm_router is None or not self.llm_router.available:
            return None
        try:
            tools = self.llm_router.resolve_tools(
                intent, describe_tools_for_llm(self.config.max_risk)
            )
        except SecurityError:
            return None
        allowed = set()
        for name in tools:
            tool = get_tool(name)
            if tool is not None and tool.risk.rank <= self.config.max_risk.rank:
                allowed.add(name)
        return allowed or None

    def describe(self) -> str:
        """返回当前会话可用工具描述（最小权限视图）。"""
        return describe_tools(self.config.max_risk)
