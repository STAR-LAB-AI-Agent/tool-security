"""安全策略的数据结构与持久化（M1）。

策略是一份「覆盖层」：字段为空（空列表 / None / 默认值）表示「未配置，沿用代码内默认」。
配置期（自然语言交互）写入本策略文件，运行期加载后覆盖代码内默认值。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .security import RiskLevel


@dataclass
class ToolPolicy:
    """单个工具的权限策略。"""

    allowed: bool = True
    risk: Optional[RiskLevel] = None  # None 表示沿用注册表默认风险

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk": self.risk.value if self.risk is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolPolicy":
        allowed = bool(data.get("allowed", True))
        risk_raw = data.get("risk")
        # 非法风险值会抛 ValueError，显式暴露坏数据（fail-fast）。
        risk = RiskLevel(risk_raw) if risk_raw else None
        return cls(allowed=allowed, risk=risk)


@dataclass
class Policy:
    """完整安全策略（运行期加载、配置期写入）。"""

    max_risk: RiskLevel = RiskLevel.HIGH
    auto_approve: bool = False
    tool_policies: Dict[str, ToolPolicy] = field(default_factory=dict)
    directory_whitelist: List[str] = field(default_factory=list)
    command_whitelist: List[str] = field(default_factory=list)
    confirm_required: List[str] = field(default_factory=list)
    # 安全控制是否激活：False 为休眠态（业务工具旁路执行），True 为运行态（门控生效）。
    # 由自然语言触发配置工具成功后置为 True 并持久化。
    enabled: bool = False
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "max_risk": self.max_risk.value,
            "auto_approve": self.auto_approve,
            "tool_policies": {k: v.to_dict() for k, v in self.tool_policies.items()},
            "directory_whitelist": self.directory_whitelist,
            "command_whitelist": self.command_whitelist,
            "confirm_required": self.confirm_required,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        max_risk = RiskLevel(data.get("max_risk", "high"))
        tool_policies = {
            name: ToolPolicy.from_dict(entry)
            for name, entry in (data.get("tool_policies") or {}).items()
        }
        return cls(
            max_risk=max_risk,
            auto_approve=bool(data.get("auto_approve", False)),
            tool_policies=tool_policies,
            directory_whitelist=list(data.get("directory_whitelist") or []),
            command_whitelist=list(data.get("command_whitelist") or []),
            confirm_required=list(data.get("confirm_required") or []),
            enabled=bool(data.get("enabled", False)),
            version=int(data.get("version", 1)),
        )


def load_policy(path: Union[str, Path]) -> Policy:
    """从 policy.json 加载策略；文件不存在时返回默认策略。"""
    p = Path(path)
    if not p.is_file():
        return Policy()
    data = json.loads(p.read_text(encoding="utf-8"))
    return Policy.from_dict(data)


def save_policy(policy: Policy, path: Union[str, Path]) -> None:
    """把策略写入 policy.json（原子写：先写临时文件再替换）。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(policy.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    tmp.replace(p)
