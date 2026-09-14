"""目录白名单：限制工具只能访问指定根目录内的路径，禁止越界。"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Union

from .security import SecurityError


class DirectoryPolicy:
    """目录白名单策略：所有文件路径必须落在 allowed_roots 之一内。

    unrestricted=True 时关闭目录校验（休眠态旁路执行使用），仅保留 root 作为相对路径基准。
    """

    def __init__(self, allowed_roots: List[Union[str, Path]], unrestricted: bool = False):
        if not allowed_roots:
            raise ValueError("至少需要一个允许的根目录")
        self.allowed_roots = [Path(r).expanduser().resolve() for r in allowed_roots]
        self.unrestricted = unrestricted

    @property
    def root(self) -> Path:
        """主根目录（同时作为命令执行的工作目录）。"""
        return self.allowed_roots[0]

    def resolve(self, raw_path: Union[str, Path]) -> Path:
        """解析路径；unrestricted 时直接返回，否则校验必须落在白名单目录内。"""
        p = Path(raw_path).expanduser()
        if not p.is_absolute():
            p = self.root / p
        p = p.resolve()
        if self.unrestricted:
            return p
        for root in self.allowed_roots:
            try:
                p.relative_to(root)
                return p
            except ValueError:
                continue
        raise SecurityError(
            f"目录白名单拦截：路径 '{raw_path}' 不在允许目录内。允许目录：{self.allowed_roots}"
        )


@dataclass
class RuntimePolicy:
    """运行时策略上下文：把「目录白名单 + 命令白名单」聚合后传给工具函数。

    工具函数统一以本对象为第一个参数（沿用旧名 `policy`），内部通过 `resolve` / `root`
    访问目录策略、通过 `command_allowlist` 访问命令白名单。
    """

    directory: DirectoryPolicy
    command_allowlist: Dict[str, str]

    @property
    def root(self) -> Path:
        return self.directory.root

    def resolve(self, raw_path: Union[str, Path]) -> Path:
        return self.directory.resolve(raw_path)
