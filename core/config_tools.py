"""安全配置工具与配置执行器（M2）。

配置工具是「元操作」：它们修改安全策略（Policy）本身，而不是执行业务动作。
因此配置工具走独立的 ConfigExecutor，与业务 ToolGateway 的区别在于：
- 不适用目录/命令白名单（配置不涉及文件/命令执行）；
- 必须强制用户确认（auto_approve 不生效），防止智能体静默给自己开权限。

M2 只交付「可路由 + 可执行（改 Policy 草稿）」；多轮确认向导在 M3，
策略落盘与运行期加载在 M4。
"""
from __future__ import annotations

import inspect
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from .assessor import assess_builtin_tools, assess_tool_source
from .audit import AuditLogger
from .guard import confirm_operation
from .policy_store import Policy, ToolPolicy, save_policy
from .registry import TOOL_REGISTRY
from .security import AgentConfig, RiskLevel, SecurityError, Tool, ToolResult


def _coerce_bool(value: Any) -> bool:
    """把 LLM 可能输出的 "true"/"false"/"允许" 等转换为布尔值。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on", "允许", "是")
    return bool(value)


def _parse_risk(value: str) -> RiskLevel:
    try:
        return RiskLevel(str(value).strip().lower())
    except ValueError:
        raise SecurityError(f"无效风险等级 '{value}'，可选：low/medium/high") from None


# --------------------------------------------------------------------------- 工具实现
def _set_max_risk(policy: Policy, risk: str) -> Dict[str, Any]:
    policy.max_risk = _parse_risk(risk)
    return {"max_risk": policy.max_risk.value}


def _set_tool_policy(
    policy: Policy,
    tool: str,
    allowed: Any = None,
    risk: Optional[str] = None,
) -> Dict[str, Any]:
    if allowed is None and risk is None:
        raise SecurityError("set_tool_policy 至少需要指定 allowed 或 risk 之一")
    entry = policy.tool_policies.get(tool, ToolPolicy())
    if allowed is not None:
        entry.allowed = _coerce_bool(allowed)
    if risk is not None:
        entry.risk = _parse_risk(risk)
    policy.tool_policies[tool] = entry
    return {
        "tool": tool,
        "allowed": entry.allowed,
        "risk": entry.risk.value if entry.risk is not None else None,
    }


def _add_directory_whitelist(
    policy: Policy, path: str, action: str = "add"
) -> Dict[str, Any]:
    if action not in ("add", "remove"):
        raise SecurityError(f"无效操作 '{action}'，可选：add/remove")
    if action == "add" and path not in policy.directory_whitelist:
        policy.directory_whitelist.append(path)
    elif action == "remove" and path in policy.directory_whitelist:
        policy.directory_whitelist.remove(path)
    return {"directory_whitelist": list(policy.directory_whitelist)}


def _add_command_whitelist(
    policy: Policy, command: str, action: str = "add"
) -> Dict[str, Any]:
    if action not in ("add", "remove"):
        raise SecurityError(f"无效操作 '{action}'，可选：add/remove")
    if action == "add" and command not in policy.command_whitelist:
        policy.command_whitelist.append(command)
    elif action == "remove" and command in policy.command_whitelist:
        policy.command_whitelist.remove(command)
    return {"command_whitelist": list(policy.command_whitelist)}


def _configure_tools(
    policy: Policy,
    input_fn: Callable[[str], str] = input,
) -> Dict[str, Any]:
    """多轮确认向导：展示工具清单 → 逐项确认 → 最终确认写入。

    input_fn 可注入（默认 input），便于测试与非交互式场景替换。
    """
    for name, tool in TOOL_REGISTRY.items():
        current = policy.tool_policies.get(name, ToolPolicy(allowed=True))
        risk_label = current.risk.value if current.risk is not None else tool.risk.value
        answer = input_fn(
            f"  - {name}（{tool.description}）当前允许={current.allowed} "
            f"风险={risk_label}；允许？[y/N/回车] "
        ).strip().lower()
        if answer == "":
            continue
        entry = policy.tool_policies.setdefault(name, ToolPolicy())
        entry.allowed = answer in ("y", "yes")
        if entry.allowed:
            risk_answer = input_fn(
                f"    风险等级？[low/medium/high，回车=保持] "
            ).strip().lower()
            if risk_answer:
                entry.risk = _parse_risk(risk_answer)

    final = input_fn("以上配置是否写入生效？[y/N] ").strip().lower()
    if final not in ("y", "yes"):
        raise SecurityError("用户取消配置，未做任何修改")
    return policy.to_dict()


def _assess_tool(
    policy: Policy,
    name: Optional[str] = None,
    source: Optional[str] = None,
    requirements: Optional[str] = None,
) -> Dict[str, Any]:
    """接入并评估一个第三方工具：bandit 划风险、pip-audit 判准入，结果写入策略。"""
    if not name or not source:
        raise SecurityError("assess_tool 需要 name（工具名）与 source（源码路径）两个参数")
    req_path = Path(requirements) if requirements else None
    assessment = assess_tool_source(name, Path(source), requirement_path=req_path)
    policy.tool_policies[name] = ToolPolicy(
        allowed=assessment.allowed, risk=assessment.risk
    )
    return assessment.to_dict()


def _assess_builtin_tools(policy: Policy) -> Dict[str, Any]:
    """用 bandit 自动评估内置工具的风险等级（只上调、不降级、不覆盖用户显式禁用）。"""
    assessed = assess_builtin_tools()
    for name, tp in assessed.items():
        existing = policy.tool_policies.get(name)
        if existing is None:
            policy.tool_policies[name] = tp
        elif existing.risk is None or tp.risk.rank > existing.risk.rank:
            existing.risk = tp.risk
    return {
        "assessed": sorted(assessed),
        "tool_policies": {k: v.to_dict() for k, v in policy.tool_policies.items()},
    }


# --------------------------------------------------------------------------- 注册表
CONFIG_REGISTRY: Dict[str, Tool] = {
    "configure_tools": Tool(
        name="configure_tools",
        description="查看当前工具安全控制策略，进入权限配置向导",
        func=_configure_tools,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="无必填参数",
    ),
    "set_tool_policy": Tool(
        name="set_tool_policy",
        description="设置某个工具是否允许调用及其风险等级",
        func=_set_tool_policy,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="tool（工具名，必填）; allowed（true/false，可选）; risk（low/medium/high，可选）",
    ),
    "set_max_risk": Tool(
        name="set_max_risk",
        description="设置当前会话允许的最高风险等级（最小权限上限）",
        func=_set_max_risk,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="risk（low/medium/high，必填）",
    ),
    "add_directory_whitelist": Tool(
        name="add_directory_whitelist",
        description="在目录白名单中新增或移除一个允许访问的目录",
        func=_add_directory_whitelist,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="path（目录路径，必填）; action（add/remove，默认 add）",
    ),
    "add_command_whitelist": Tool(
        name="add_command_whitelist",
        description="在命令白名单中新增或移除一个允许执行的命令",
        func=_add_command_whitelist,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="command（命令，必填）; action（add/remove，默认 add）",
    ),
    "assess_tool": Tool(
        name="assess_tool",
        description="接入并评估一个第三方工具：bandit 扫描源码划分风险等级，pip-audit 审计依赖漏洞判定白名单准入",
        func=_assess_tool,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="name（工具名，必填）; source（源码文件路径，必填）; requirements（依赖文件路径，可选）",
    ),
    "assess_builtin_tools": Tool(
        name="assess_builtin_tools",
        description="用 bandit 自动评估内置工具的风险等级（安全控制机制自检）",
        func=_assess_builtin_tools,
        risk=RiskLevel.HIGH,
        category="安全配置",
        params_desc="无必填参数",
    ),
}


def get_config_tool(name: str) -> Optional[Tool]:
    """配置白名单查询：未注册的配置工具返回 None。"""
    return CONFIG_REGISTRY.get(name)


def describe_config_tools_for_llm() -> str:
    """生成注入给 LLM 的配置工具描述（供路由选择与参数抽取）。"""
    lines = []
    for t in CONFIG_REGISTRY.values():
        lines.append(f"- {t.name}：{t.description}；参数：{t.params_desc}")
    return "\n".join(lines)


def describe_config_tools() -> str:
    """生成面向用户/日志的配置工具清单。"""
    lines = []
    for t in CONFIG_REGISTRY.values():
        lines.append(f"- {t.name} [{t.risk.value}]：{t.description}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- 执行器
def _filter_params(tool: Tool, params: Dict[str, Any]) -> Dict[str, Any]:
    """按配置工具函数签名过滤参数，丢弃调用方多给的键。"""
    allowed = set(inspect.signature(tool.func).parameters) - {"policy"}
    return {k: v for k, v in params.items() if k in allowed}


class ConfigExecutor:
    """配置工具的安全执行器：白名单 → 强制确认 → 执行 → 审计。"""

    def __init__(
        self,
        policy: Policy,
        audit_logger: AuditLogger,
        config: AgentConfig,
        session_id: str,
        *,
        input_fn: Optional[Callable[[str], str]] = None,
        policy_path: Optional[Union[str, Path]] = None,
    ):
        self.policy = policy
        self.audit = audit_logger
        self.config = config
        self.session_id = session_id
        self.input_fn = input_fn if input_fn is not None else input
        self.policy_path = policy_path

    def execute(
        self,
        tool_name: str,
        params: Dict[str, Any],
        *,
        intent_label: str = "",
    ) -> ToolResult:
        started = time.perf_counter()

        tool = get_config_tool(tool_name)
        if tool is None:
            reason = f"配置白名单拦截：未注册的配置工具 '{tool_name}' 不允许调用"
            self.audit.record(
                self.session_id, intent_label, tool_name, RiskLevel.HIGH,
                sorted(params.keys()), "blocked", reason, False,
                (time.perf_counter() - started) * 1000, reason,
            )
            return ToolResult(ok=False, error=reason, decision="blocked")

        params = _filter_params(tool, params)
        params_keys = sorted(params.keys())

        def _record(decision: str, reason: str, error: Optional[str] = None) -> ToolResult:
            self.audit.record(
                self.session_id, intent_label, tool_name, tool.risk, params_keys,
                decision, reason, False, (time.perf_counter() - started) * 1000, error,
            )
            return ToolResult(ok=False, error=error or reason, decision=decision)

        # 强制确认：配置动作必须经用户确认，auto_approve 不生效。
        res = confirm_operation(
            tool, params_keys,
            confirm_fn=self.config.confirm_fn,
            auto_approve=False,
        )
        if not res.approved:
            return _record("denied", res.reason, res.reason)

        try:
            if tool_name == "configure_tools":
                data = tool.func(self.policy, input_fn=self.input_fn)
            else:
                data = tool.func(self.policy, **params)
            if self.policy_path is not None:
                save_policy(self.policy, self.policy_path)
            self.audit.record(
                self.session_id, intent_label, tool_name, tool.risk, params_keys,
                "allowed", "配置成功", True, (time.perf_counter() - started) * 1000,
                detail=data,
            )
            return ToolResult(ok=True, data=data, decision="allowed")
        except SecurityError as e:
            return _record("blocked", str(e), str(e))
        except Exception as e:  # 兜底，避免配置异常导致智能体失控
            reason = f"配置异常：{e}"
            return _record("error", reason, reason)
