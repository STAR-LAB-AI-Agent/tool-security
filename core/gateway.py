"""独立的工具安全执行网关：把「决策」安全地落地为「执行」，可被任意智能体接入。

这是题目 26 的可交付能力本体——任何智能体（nanobot / 自研 LLM 入口等）只要持有
本网关，把工具注册进 registry 并配置好 directory_policy，即可让它的工具调用获得
「工具白名单 / 目录白名单 / 危险操作确认 / 最小权限」等约束，而不依赖某个具体智能体实现。
"""
from __future__ import annotations

import dataclasses
import inspect
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Set

from .audit import AuditLogger
from .directory_policy import DirectoryPolicy, RuntimePolicy
from .guard import confirm_operation
from .policy_store import Policy
from .registry import get_tool
from .security import AgentConfig, RiskLevel, SecurityError, Tool, ToolResult
from .tools import COMMAND_ALLOWLIST


class ToolGateway:
    """工具安全执行网关。

    职责边界：接收 (工具名, 参数) 决策 → 穿过全部安全闸门 → 执行 → 审计 → 返回结构化结果。
    网关不信任任何决策内容，无论决策来自 LLM、关键词还是外部调用方，都逐道闸门重新校验。
    """

    def __init__(
        self,
        directory_policy: DirectoryPolicy,
        audit_logger: AuditLogger,
        config: AgentConfig | None = None,
        policy: Policy | None = None,
    ):
        self.audit = audit_logger
        self.config = config or AgentConfig()
        # policy 为持久化安全策略（policy.json 的覆盖层）；None 时表示未加载，使用默认。
        self.security_policy = policy or Policy()
        self.directory_policy = self._build_directory_policy(directory_policy)
        self.command_allowlist = self._build_command_allowlist()
        self.runtime_policy = RuntimePolicy(self.directory_policy, self.command_allowlist)
        self.session_id = uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------ 策略合并
    def _build_directory_policy(self, base: DirectoryPolicy) -> DirectoryPolicy:
        """把持久化策略中的目录白名单追加到代码内目录策略（空则沿用默认）。"""
        extra = self.security_policy.directory_whitelist
        if not extra:
            return base
        roots = list(base.allowed_roots)
        for entry in extra:
            p = Path(entry).expanduser()
            if not p.is_absolute():
                p = base.root / p
            roots.append(p)
        return DirectoryPolicy(roots)

    def _build_command_allowlist(self) -> Dict[str, str]:
        """持久化命令白名单非空时替换默认白名单，否则沿用代码内默认。"""
        whitelist = self.security_policy.command_whitelist
        if not whitelist:
            return COMMAND_ALLOWLIST
        return {cmd: "" for cmd in whitelist}

    def _effective_risk(self, tool: Tool) -> RiskLevel:
        """单个工具的风险覆盖：持久化策略未指定风险时沿用注册表默认。"""
        override = self.security_policy.tool_policies.get(tool.name)
        if override is not None and override.risk is not None:
            return override.risk
        return tool.risk

    def _effective_max_risk(self) -> RiskLevel:
        """会话最小权限上限取更严格者：会话配置与持久化策略两者中风险上限更低者。"""
        cfg = self.config.max_risk
        pol = self.security_policy.max_risk
        return cfg if cfg.rank <= pol.rank else pol

    def execute(
        self,
        tool_name: str,
        params: Dict[str, Any],
        *,
        intent_label: str = "",
        allowed_tools: Optional[Set[str]] = None,
    ) -> ToolResult:
        """执行一次受安全约束的工具调用，返回结构化结果（不抛业务异常）。

        allowed_tools：本次任务自动推导出的最小工具集（可选）。若提供，则只有
        集合内的工具可被调用，其余即便已注册、风险达标也一律拦截。
        """
        started = time.perf_counter()

        # 闸门 1：工具白名单（未注册工具按最高风险处理，默认拒绝并落审计）
        tool = get_tool(tool_name)
        if tool is None:
            reason = f"工具白名单拦截：未注册的工具 '{tool_name}' 不允许调用"
            self.audit.record(
                self.session_id, intent_label, tool_name, RiskLevel.HIGH,
                sorted(params.keys()), "blocked", reason, False,
                (time.perf_counter() - started) * 1000, reason,
            )
            return ToolResult(ok=False, error=reason, decision="blocked")

        params = self._filter_params(tool, params)
        params_keys = sorted(params.keys())
        effective_risk = self._effective_risk(tool)

        def _record(decision: str, reason: str, error: str | None = None) -> ToolResult:
            self.audit.record(
                self.session_id, intent_label, tool_name, effective_risk, params_keys,
                decision, reason, False, (time.perf_counter() - started) * 1000, error,
            )
            return ToolResult(ok=False, error=error or reason, decision=decision)

        # 闸门 1.2：持久化工具策略（显式禁用优先于其余判断）
        override = self.security_policy.tool_policies.get(tool_name)
        if override is not None and not override.allowed:
            reason = f"工具策略拦截：工具 '{tool_name}' 已被安全策略禁用"
            return _record("blocked", reason, reason)

        # 闸门 1.5：任务级最小权限集（自动推导）。不在集合内则拦截。
        if allowed_tools is not None and tool_name not in allowed_tools:
            reason = (
                f"最小权限拦截：工具 '{tool_name}' 不在本次任务自动推导的最小工具集内，"
                f"允许的工具：{sorted(allowed_tools)}"
            )
            return _record("blocked", reason, reason)

        # 闸门 2：最小权限（能力门控，使用覆盖后的风险与上限）
        max_risk = self._effective_max_risk()
        if effective_risk.rank > max_risk.rank:
            reason = (
                f"最小权限拦截：当前会话最大风险 {max_risk.value}，"
                f"工具风险 {effective_risk.value}"
            )
            return _record("blocked", reason, reason)

        # 闸门 3：危险操作确认（覆盖后的风险 / 强制确认清单同样生效）
        needs_confirmation = (
            tool.requires_confirmation
            or effective_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH)
            or tool_name in self.security_policy.confirm_required
        )
        if needs_confirmation:
            confirm_tool = dataclasses.replace(
                tool, risk=effective_risk, requires_confirmation=True,
            )
            res = confirm_operation(
                confirm_tool, params_keys,
                confirm_fn=self.config.confirm_fn,
                auto_approve=self.config.auto_approve,
            )
            if not res.approved:
                return _record("denied", res.reason, res.reason)

        # 闸门 4/5：目录白名单 + 命令白名单（工具内部） + 执行
        try:
            data = tool.func(self.runtime_policy, **params)
            result = ToolResult(ok=True, data=data, decision="allowed")
            self.audit.record(
                self.session_id, intent_label, tool_name, effective_risk, params_keys,
                "allowed", "执行成功", True, (time.perf_counter() - started) * 1000,
            )
            return result
        except SecurityError as e:
            return _record("blocked", str(e), str(e))
        except Exception as e:  # 兜底异常处理，避免网关失控
            reason = f"执行异常：{e}"
            return _record("error", reason, reason)

    @staticmethod
    def _filter_params(tool: Tool, params: Dict[str, Any]) -> Dict[str, Any]:
        """按工具函数签名过滤参数，丢弃调用方可能多给的键，避免 TypeError。"""
        allowed = set(inspect.signature(tool.func).parameters) - {"policy"}
        return {k: v for k, v in params.items() if k in allowed}
