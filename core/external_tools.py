"""外部接入工具：subprocess 执行 + 注册记录持久化。

外部工具是独立的 Skill + Script 项目（自带 SKILL.md + cli.py + core/ 等）。
它们被 import_tool 接入后，整包复制到 external/<name>/，其脚本入口通过
subprocess 由本网关调用；注册信息持久化到 config/external_tools.json，
以便每次启动 cli.py 时恢复注册，否则动态注册会在进程结束后丢失。
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .registry import register_tool
from .security import ExternalToolSpec, RiskLevel, SecurityError, Tool

_EXTERNAL_TIMEOUT = 30


@dataclass
class ExternalToolRecord:
    """外部工具的持久化注册记录（可 JSON 序列化）。"""

    name: str
    description: str
    workdir: str
    entry: str = "cli.py"
    tool_name: Optional[str] = None
    risk: str = "low"
    category: str = "外部接入"
    params_desc: str = ""
    enabled_by_default: bool = False  # 外部工具默认 deny-by-default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "workdir": self.workdir,
            "entry": self.entry,
            "tool_name": self.tool_name,
            "risk": self.risk,
            "category": self.category,
            "params_desc": self.params_desc,
            "enabled_by_default": self.enabled_by_default,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExternalToolRecord":
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            workdir=str(data["workdir"]),
            entry=str(data.get("entry", "cli.py")),
            tool_name=data.get("tool_name"),
            risk=str(data.get("risk", "low")),
            category=str(data.get("category", "外部接入")),
            params_desc=str(data.get("params_desc", "")),
            enabled_by_default=bool(data.get("enabled_by_default", False)),
        )


def run_external_tool(
    spec: ExternalToolSpec,
    params: Dict[str, Any],
    timeout: int = _EXTERNAL_TIMEOUT,
) -> Dict[str, Any]:
    """通过 subprocess 调用外部工具的脚本入口，返回结构化结果。

    调用约定与统一 Skill + Script 接口一致：目标 cli.py 支持
    `--tool <name> --param k=v`。参数以 key=value 透传。
    """
    workdir = Path(spec.workdir)
    entry = workdir / spec.entry
    if not entry.is_file():
        raise SecurityError(f"外部工具入口不存在：{entry}")
    cmd = [sys.executable, str(entry)]
    if spec.tool_name:
        cmd += ["--tool", spec.tool_name]
    for k, v in params.items():
        cmd += ["--param", f"{k}={v}"]
    try:
        proc = subprocess.run(
            cmd, cwd=str(workdir), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SecurityError(f"外部工具执行超时（>{timeout}s）已终止") from e
    return {
        "entry": str(entry),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:2000],
        "stderr": proc.stderr[:2000],
    }


def record_to_tool(record: ExternalToolRecord) -> Tool:
    """把持久化记录还原为注册表 Tool（外部 subprocess 工具）。"""
    return Tool(
        name=record.name,
        description=record.description,
        risk=RiskLevel(record.risk),
        func=None,
        category=record.category,
        params_desc=record.params_desc,
        external=ExternalToolSpec(
            workdir=record.workdir,
            entry=record.entry,
            tool_name=record.tool_name,
        ),
        enabled_by_default=record.enabled_by_default,
    )


def load_external_tools(path: Path) -> List[ExternalToolRecord]:
    """从磁盘加载外部工具注册表；文件不存在时返回空列表。"""
    p = Path(path)
    if not p.is_file():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    return [ExternalToolRecord.from_dict(item) for item in data]


def save_external_tools(records: List[ExternalToolRecord], path: Path) -> None:
    """把外部工具注册表写入磁盘（原子写）。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps([r.to_dict() for r in records], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(p)


def register_external_tools_from_disk(path: Path) -> int:
    """启动时调用：把磁盘上的外部工具恢复注册进 TOOL_REGISTRY，返回注册数量。"""
    count = 0
    for record in load_external_tools(path):
        register_tool(record_to_tool(record))
        count += 1
    return count
