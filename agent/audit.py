"""完整操作审计日志：以 JSON Lines 追加写盘，不记录敏感参数值。"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .security import RiskLevel


class AuditLogger:
    """把每一次工具调用（含拦截/拒绝/异常）落盘，支持事后回溯。"""

    def __init__(self, log_path: Union[str, Path]):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        session_id: str,
        intent: str,
        tool_name: str,
        risk: RiskLevel,
        params_keys: List[str],
        decision: str,
        reason: str,
        ok: bool,
        duration_ms: float,
        error: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        entry: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "session_id": session_id,
            "intent": intent,
            "tool": tool_name,
            "risk": risk.value,
            # 只记录参数键名，不记录参数值，规避密码/密钥等敏感信息泄漏
            "params_keys": params_keys,
            "decision": decision,
            "reason": reason,
            "ok": ok,
            "duration_ms": round(duration_ms, 2),
        }
        if error:
            entry["error"] = error
        # detail 仅用于配置类变更，记录「改了什么」以支持回溯（普通业务不记录参数值）
        if detail is not None:
            entry["detail"] = detail
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
