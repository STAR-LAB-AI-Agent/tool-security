"""AI Agent 工具安全控制 —— 核心安全模块。

本包实现题目 26「AI Agent 工具安全控制」的最小权限机制：
- 工具白名单（registry.py）
- 目录白名单（directory_policy.py）
- 危险操作确认（guard.py）
- 最小权限（registry.py 的风险分级 + 能力门控）
- 完整操作审计日志（audit.py）
"""
