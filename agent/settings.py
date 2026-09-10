"""零依赖的 .env 读取：从项目目录向上查找并解析 KEY=VALUE 配置。

刻意不用 python-dotenv，保持项目纯标准库、无第三方运行依赖。
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional


def _find_dotenv(start: Path, max_depth: int = 5) -> Optional[Path]:
    """从 start 目录向上逐层查找 .env 文件（支持父目录共享配置）。"""
    cur = start.resolve()
    for _ in range(max_depth):
        candidate = cur / ".env"
        if candidate.is_file():
            return candidate
        if cur.parent == cur:  # 已到文件系统根目录
            break
        cur = cur.parent
    return None


def load_dotenv(start: Path) -> Dict[str, str]:
    """解析 .env 为字典，忽略注释与空行，不做类型转换。

    说明：本函数只负责读取，不会把内容写进进程环境变量，避免污染全局状态。
    """
    path = _find_dotenv(start)
    if path is None:
        return {}

    result: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            result[key] = value
    return result
