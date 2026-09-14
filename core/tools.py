"""具体工具实现。所有文件类工具都经过目录白名单校验，命令类工具经过命令白名单校验。"""
from __future__ import annotations

import subprocess
from typing import Any, Dict

from .directory_policy import RuntimePolicy
from .security import SecurityError

# 命令白名单：仅允许这些前缀开头的命令，其余一律拦截，防止任意命令执行。
COMMAND_ALLOWLIST = {
    "ls": "列出目录内容",
    "dir": "列出目录内容(Windows)",
    "pwd": "打印当前目录",
    "echo": "回显文本",
    "python --version": "查看 Python 版本",
    "nmap --version": "查看 nmap 版本",
}

# 命令全放行哨兵：休眠态旁路执行时使用，跳过命令白名单校验。
ALL_COMMANDS = {"__all__": "允许任意命令（休眠态旁路）"}


def _check_command(command: str, allowlist=None) -> None:
    """命令白名单校验：命令必须命中允许的前缀。

    allowlist 为 ALL_COMMANDS 时直接放行（休眠态旁路）；为 None 时用默认白名单。
    """
    cmd = command.strip()
    if allowlist is ALL_COMMANDS:
        return
    allowlist = COMMAND_ALLOWLIST if allowlist is None else allowlist
    for allowed in allowlist:
        if cmd == allowed or cmd.startswith(allowed + " "):
            return
    raise SecurityError(
        f"命令白名单拦截：命令 '{cmd}' 不在允许列表中。允许的命令前缀：{sorted(allowlist)}"
    )


def list_dir(policy: RuntimePolicy, path: str = ".") -> Dict[str, Any]:
    """列出目录内容（LOW，只读）。"""
    target = policy.resolve(path)
    if not target.is_dir():
        raise SecurityError(f"路径不是目录：{path}")
    entries = sorted(e.name for e in target.iterdir())
    return {"path": str(target), "entries": entries}


def read_file(policy: RuntimePolicy, path: str, max_chars: int = 2000) -> Dict[str, Any]:
    """读取文本文件内容（LOW，只读）。默认截断到 max_chars，体现低 Token 要求。"""
    target = policy.resolve(path)
    if not target.is_file():
        raise SecurityError(f"路径不是文件：{path}")
    content = target.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(target),
        "content": content[:max_chars],
        "truncated": len(content) > max_chars,
        "total_chars": len(content),
    }


def write_file(policy: RuntimePolicy, path: str, content: str) -> Dict[str, Any]:
    """写入文本文件（MEDIUM，需确认）。"""
    target = policy.resolve(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": str(target), "written_chars": len(content)}


def delete_file(policy: RuntimePolicy, path: str) -> Dict[str, Any]:
    """删除文件（HIGH，需确认）。仅支持删除文件，不支持删除目录。"""
    target = policy.resolve(path)
    if not target.exists():
        raise SecurityError(f"路径不存在：{path}")
    if target.is_dir():
        raise SecurityError("仅支持删除文件，不支持删除目录")
    target.unlink()
    return {"path": str(target), "deleted": True}


def run_command(policy: RuntimePolicy, command: str, timeout: int = 30) -> Dict[str, Any]:
    """执行命令（HIGH，需确认）。命令白名单 + 固定工作目录 + 超时三重限制。"""
    _check_command(command, policy.command_allowlist)
    cwd = policy.root
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SecurityError(f"命令执行超时（>{timeout}s）已终止") from e
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:2000],
        "stderr": proc.stderr[:2000],
    }
