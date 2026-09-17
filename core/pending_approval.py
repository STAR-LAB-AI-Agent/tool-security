"""显式批准机制：待批准请求（两段式，供非交互 Agent 环境使用）。

安全背景
--------
配置工具（set_max_risk / set_tool_policy / confirm_tool_risk 等）修改的是安全策略本身，
属于高危元操作，必须由人类显式授权，且 `--auto-approve` 对其不生效。但在 nanobot 等
Agent Runtime 中，工具调用发生在非交互子进程（无 TTY），无法就地 `input()` 确认：
直接放行会削弱安全边界，直接拒绝则 Agent 永远无法改配置。

折中方案（两段式待批准）
------------------------
1. Agent 在非交互环境调用配置工具 → 生成一条「待批准请求」并返回 `request_id`，
   此时**不做任何策略修改**；
2. 人类在本机交互终端执行 `python cli.py --approve <request_id>`，逐条审查后批准；
3. Agent 携带 `--pending-id <request_id>` 重放同一调用 → 校验通过（已批准 / 未过期 /
   工具与参数完全一致）后才真正执行，且请求被**一次性消费**。

安全性质
--------
- 请求只绑定「工具 + 精确参数」，不可跨工具 / 跨参数复用；
- 每条请求一次性消费，审批后默认 10 分钟内未重放即过期；
- 请求文件位于 `logs/pending/`（目录白名单之外），不参与业务文件访问。
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_TTL_SECONDS = 600  # 10 分钟


@dataclass
class PendingApproval:
    """一条待批准请求：人类批准前不生效，批准后只能重放一次。"""

    id: str
    tool: str
    params: Dict[str, Any]
    status: str  # pending / approved
    created_at: float
    expires_at: float
    approved_at: Optional[float] = None
    intent_label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "params": self.params,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approved_at": self.approved_at,
            "intent_label": self.intent_label,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PendingApproval":
        return cls(
            id=str(data["id"]),
            tool=str(data["tool"]),
            params=dict(data.get("params") or {}),
            status=str(data.get("status", "pending")),
            created_at=float(data.get("created_at", 0)),
            expires_at=float(data.get("expires_at", 0)),
            approved_at=float(data["approved_at"]) if data.get("approved_at") else None,
            intent_label=str(data.get("intent_label", "")),
        )


class PendingStore:
    """待批准请求的磁盘存储：每个请求一个 JSON 文件（原子写）。"""

    def __init__(self, root: Path, ttl: int = DEFAULT_TTL_SECONDS):
        self.root = Path(root)
        self.ttl = ttl
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, request_id: str) -> Path:
        return self.root / f"{request_id}.json"

    def create(
        self,
        tool: str,
        params: Dict[str, Any],
        intent_label: str = "",
        ttl: Optional[int] = None,
    ) -> PendingApproval:
        request_id = secrets.token_hex(8)  # 64 位随机，不可猜测
        now = time.time()
        req = PendingApproval(
            id=request_id,
            tool=tool,
            params=dict(params),
            status="pending",
            created_at=now,
            expires_at=now + (ttl if ttl is not None else self.ttl),
            intent_label=intent_label,
        )
        self._write(req)
        return req

    def load(self, request_id: str) -> Optional[PendingApproval]:
        p = self._path(request_id)
        if not p.is_file():
            return None
        try:
            return PendingApproval.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return None

    def approve(self, request_id: str) -> Tuple[bool, str]:
        """人类批准：仅当请求仍为 pending 且未过期。"""
        req = self.load(request_id)
        if req is None:
            return False, f"待批准请求 '{request_id}' 不存在"
        if req.status != "pending":
            return False, f"待批准请求 '{request_id}' 状态为 {req.status}，无需批准"
        if req.expires_at < time.time():
            self._path(request_id).unlink(missing_ok=True)
            return False, f"待批准请求 '{request_id}' 已过期"
        req.status = "approved"
        req.approved_at = time.time()
        self._write(req)
        return True, "已批准"

    def deny(self, request_id: str) -> bool:
        if not self._path(request_id).is_file():
            return False
        self._path(request_id).unlink(missing_ok=True)
        return True

    def consume(
        self, request_id: str, tool: str, params: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """重放执行前的校验与一次性消费：已批准 + 未过期 + 工具/参数完全一致。"""
        req = self.load(request_id)
        if req is None:
            return False, f"待批准请求 '{request_id}' 不存在或已被消费"
        if req.status != "approved":
            return False, f"待批准请求 '{request_id}' 尚未被人类批准（状态={req.status}）"
        if req.expires_at < time.time():
            self._path(request_id).unlink(missing_ok=True)
            return False, f"待批准请求 '{request_id}' 已过期，请重新发起"
        if req.tool != tool:
            return False, f"待批准请求与当前工具不匹配（请求={req.tool}，当前={tool}）"
        if req.params != dict(params):
            return False, "待批准请求与当前参数不一致，不允许复用"
        self._path(request_id).unlink(missing_ok=True)  # 一次性消费
        return True, "待批准请求已消费"

    def list_pending(self) -> List[PendingApproval]:
        now = time.time()
        result: List[PendingApproval] = []
        for p in sorted(self.root.glob("*.json")):
            req = self.load(p.stem)
            if req is None:
                continue
            if req.status != "pending":
                continue
            if req.expires_at < now:
                p.unlink(missing_ok=True)  # 顺手清理过期项
                continue
            result.append(req)
        return result

    def _write(self, req: PendingApproval) -> None:
        tmp = self._path(req.id).with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(req.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        tmp.replace(self._path(req.id))
