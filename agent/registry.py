"""工具白名单与最小权限：统一注册表 + 风险分级 + 能力门控。"""
from __future__ import annotations

from typing import Dict, List, Optional

from . import tools as _tool_impls
from .security import RiskLevel, SecurityError, Tool

# 统一工具白名单：只有注册在此处的工具才能被智能体调用，未注册的工具一律拦截。
TOOL_REGISTRY: Dict[str, Tool] = {
    "list_dir": Tool(
        name="list_dir",
        description="列出指定目录下的文件与子目录",
        func=_tool_impls.list_dir,
        risk=RiskLevel.LOW,
        category="文件只读",
        params_desc="path（可选，默认 '.' 表示当前目录）",
    ),
    "read_file": Tool(
        name="read_file",
        description="读取文本文件内容（默认最多返回 2000 字符）",
        func=_tool_impls.read_file,
        risk=RiskLevel.LOW,
        category="文件只读",
        params_desc="path（必填）; max_chars（可选，默认 2000）",
    ),
    "write_file": Tool(
        name="write_file",
        description="向指定文件写入文本内容",
        func=_tool_impls.write_file,
        risk=RiskLevel.MEDIUM,
        category="文件写入",
        params_desc="path（必填）; content（必填）",
    ),
    "delete_file": Tool(
        name="delete_file",
        description="删除指定文件（危险操作）",
        func=_tool_impls.delete_file,
        risk=RiskLevel.HIGH,
        category="文件删除",
        params_desc="path（必填）",
    ),
    "run_command": Tool(
        name="run_command",
        description="在命令白名单范围内执行系统命令（危险操作）",
        func=_tool_impls.run_command,
        risk=RiskLevel.HIGH,
        category="命令执行",
        params_desc="command（必填）; timeout（可选，默认 30 秒）",
    ),
}


def get_tool(name: str) -> Optional[Tool]:
    """白名单查询：未注册的工具返回 None，禁止调用。"""
    return TOOL_REGISTRY.get(name)


def require_tool(name: str) -> Tool:
    """白名单强制校验：未注册的工具直接抛出 SecurityError。"""
    tool = get_tool(name)
    if tool is None:
        raise SecurityError(f"工具白名单拦截：未注册的工具 '{name}' 不允许调用")
    return tool


def expose_tools(max_risk: RiskLevel) -> List[Tool]:
    """最小权限门控：只开放风险等级不超过 max_risk 的工具。"""
    return [t for t in TOOL_REGISTRY.values() if t.risk.rank <= max_risk.rank]


def describe_tools(max_risk: RiskLevel) -> str:
    """生成注入给智能体/模型的工具能力描述（让模型「看得到但碰不到」越权工具）。"""
    lines = []
    for t in expose_tools(max_risk):
        confirm = "需要确认" if t.requires_confirmation else "无需确认"
        lines.append(f"- {t.name} [{t.risk.value} / {confirm}]：{t.description}")
    return "\n".join(lines)


def describe_tools_for_llm(max_risk: RiskLevel) -> str:
    """生成供 LLM 做参数抽取的工具描述（含参数说明，供 route 注入 system prompt）。"""
    lines = []
    for t in expose_tools(max_risk):
        lines.append(f"- {t.name}：{t.description}；参数：{t.params_desc}")
    return "\n".join(lines)
