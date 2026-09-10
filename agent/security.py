"""核心类型定义：风险等级、工具元数据、安全策略配置、执行结果与安全异常。"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


class SecurityError(Exception):
    """安全策略被触发时抛出的异常（白名单/目录/命令/最小权限等拦截）。"""


class RiskLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


@dataclass
class Tool:
    """工具元数据，是「工具白名单」的唯一登记入口。"""

    name: str
    description: str
    func: Callable[..., Any]
    risk: RiskLevel
    category: str = "通用"
    requires_confirmation: bool = False
    params_desc: str = ""  # 参数说明，注入给 LLM 用于准确抽取参数

    def __post_init__(self) -> None:
        # 默认：中/高风险操作需要用户确认，低风险只读操作自动放行
        if self.risk in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            self.requires_confirmation = True


@dataclass
class AgentConfig:
    """安全策略配置：最小权限上限 + 危险操作确认策略（供网关与智能体共用）。"""

    max_risk: RiskLevel = RiskLevel.HIGH
    auto_approve: bool = False
    confirm_fn: Optional[Callable[[Tool, List[str]], bool]] = None


@dataclass
class ToolResult:
    """工具执行的结构化结果，避免把无关内容塞回模型上下文。"""

    ok: bool
    data: Any = None
    error: Optional[str] = None
    decision: str = "allowed"  # allowed / blocked / denied / error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "data": self.data,
            "error": self.error,
            "decision": self.decision,
        }
