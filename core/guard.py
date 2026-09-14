"""危险操作确认：中/高风险操作必须获得用户明确确认后才可执行。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from .security import Tool


@dataclass
class ConfirmationResult:
    approved: bool
    reason: str


def confirm_operation(
    tool: Tool,
    params_keys: List[str],
    confirm_fn: Optional[Callable[[Tool, List[str]], bool]] = None,
    auto_approve: bool = False,
) -> ConfirmationResult:
    """危险操作确认。

    - 低风险操作：自动放行。
    - 中/高风险操作：默认需要用户确认；auto_approve 或提供 confirm_fn 时可跳过交互。
    """
    if not tool.requires_confirmation:
        return ConfirmationResult(True, "低风险操作，自动放行")

    if auto_approve:
        return ConfirmationResult(True, "auto_approve 已开启")

    if confirm_fn is not None:
        approved = bool(confirm_fn(tool, params_keys))
        return ConfirmationResult(
            approved, "用户确认通过" if approved else "用户拒绝确认"
        )

    # 交互式确认（CLI 场景）
    answer = (
        input(
            f"[危险操作确认] 即将调用工具 '{tool.name}'（风险 {tool.risk.value}），"
            f"参数键 {params_keys}，是否继续？[y/N] "
        )
        .strip()
        .lower()
    )
    approved = answer in ("y", "yes")
    return ConfirmationResult(approved, "用户确认通过" if approved else "用户拒绝确认")
