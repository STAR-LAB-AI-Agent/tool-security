"""工具接入器：把一个外部 Skill + Script 项目自动收编进安全网关。

职责：读目标 SKILL.md → 复制整项目到 external/<name>/ → 生成声明 SKILL.md
→ bandit/pip-audit 评估 → 写 external_tools.json → 动态注册进 TOOL_REGISTRY。
接入后的工具默认 deny-by-default（enabled_by_default=False），需经风险控制
流程显式准入后才可调用。
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from .assessor import assess_tool_source, explain_reasons
from .external_tools import (
    ExternalToolRecord,
    load_external_tools,
    record_to_tool,
    save_external_tools,
)
from .registry import TOOL_REGISTRY, register_tool
from .security import SecurityError


def _find_skill_md(root: Path) -> Optional[Path]:
    """定位目标项目的 SKILL.md（优先根目录，其次 skills/<name>/SKILL.md）。"""
    direct = root / "SKILL.md"
    if direct.is_file():
        return direct
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        for skill_dir in skills_dir.iterdir():
            candidate = skill_dir / "SKILL.md"
            if candidate.is_file():
                return candidate
    return None


def _parse_skill_frontmatter(md_path: Path) -> Dict[str, str]:
    """轻量解析 SKILL.md frontmatter，提取 name 与 description。"""
    text = md_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    fm = parts[1]
    meta: Dict[str, str] = {}
    m = re.search(r"^name\s*:\s*(\S+)", fm, re.MULTILINE)
    if m:
        meta["name"] = m.group(1).strip().strip("\"'")
    m = re.search(r"^description\s*:\s*(.+)", fm, re.MULTILINE)
    if m:
        meta["description"] = m.group(1).strip().strip("\"'")
    return meta


def _build_declaration(name: str, description: str) -> str:
    """生成声明 SKILL.md（放在 skills/<name>/，正文统一指向网关入口）。"""
    desc = json.dumps(f"{description}（外部接入，经工具安全控制网关执行）", ensure_ascii=False)
    return (
        "---\n"
        f"name: {name}\n"
        f"description: {desc}\n"
        'metadata: {\n'
        '  "nanobot": {\n'
        '    "emoji": "🔌",\n'
        '    "requires": {"bins": ["python"]},\n'
        '    "always": false\n'
        "  }\n"
        "}\n"
        "---\n\n"
        f"# {name}（外部接入）\n\n"
        "本能力由「工具安全控制」网关统一执行，调用方式：\n\n"
        "```\n"
        f"python cli.py --tool {name} --param key=value\n"
        "```\n\n"
        "工作目录为项目根。该工具默认拦截（deny-by-default），需先经风险控制流程准入。\n"
    )


def import_external_tool(
    project_path: str,
    *,
    name: Optional[str] = None,
    project_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """接入一个外部 Skill + Script 项目，返回接入结果。

    流程：读 SKILL.md → 复制到 external/<name>/ → 生成声明 SKILL.md →
    评估 → 持久化注册表 → 动态注册。默认 deny-by-default。
    """
    src = Path(project_path).expanduser().resolve()
    if not src.is_dir():
        raise SecurityError(f"待接入项目目录不存在：{src}")

    root = (project_root or Path(__file__).resolve().parent.parent).resolve()
    external_dir = root / "external"
    skills_dir = root / "skills"
    registry_path = root / "config" / "external_tools.json"

    # 1. 读目标 SKILL.md，确定 name 与 description
    skill_md = _find_skill_md(src)
    meta = _parse_skill_frontmatter(skill_md) if skill_md else {}
    tool_name = (name or meta.get("name") or src.name).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", tool_name):
        raise SecurityError(f"无效工具名 '{tool_name}'，仅允许字母/数字/._-")
    description = meta.get("description") or tool_name

    # 2. 重名检查
    if tool_name in TOOL_REGISTRY:
        raise SecurityError(f"工具名 '{tool_name}' 已被注册，请更换名称")
    existing = load_external_tools(registry_path)
    if any(r.name == tool_name for r in existing):
        raise SecurityError(f"工具 '{tool_name}' 已接入，请勿重复接入")

    # 3. 复制整项目到 external/<name>/
    dest = external_dir / tool_name
    if dest.exists():
        raise SecurityError(f"目标目录已存在：{dest}，请先清理或更换名称")
    shutil.copytree(
        src, dest,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", ".venv", "venv", "node_modules",
        ),
    )

    # 4. 生成声明 SKILL.md
    (skills_dir / tool_name).mkdir(parents=True, exist_ok=True)
    (skills_dir / tool_name / "SKILL.md").write_text(
        _build_declaration(tool_name, description), encoding="utf-8"
    )

    # 5. 评估：bandit 扫整个项目，pip-audit 扫 requirements.txt
    req = dest / "requirements.txt"
    assessment = assess_tool_source(
        tool_name, dest,
        requirement_path=req if req.is_file() else None,
    )

    # 6. 持久化注册记录（deny-by-default）
    record = ExternalToolRecord(
        name=tool_name,
        description=description,
        workdir=str(dest),
        entry="cli.py",
        tool_name=None,
        risk=assessment.risk.value,
        category="外部接入",
        params_desc="参数透传给外部 cli.py（key=value）",
        enabled_by_default=False,
    )
    existing.append(record)
    save_external_tools(existing, registry_path)

    # 7. 动态注册进当前进程
    register_tool(record_to_tool(record))

    return {
        "tool": tool_name,
        "description": description,
        "workdir": str(dest),
        "declaration": str(skills_dir / tool_name / "SKILL.md"),
        "risk": assessment.risk.value,
        "reasons": explain_reasons(assessment.findings, assessment.vulnerabilities),
        "pip_audit_status": assessment.pip_audit_status,
        "bandit_findings": [f.to_dict() for f in assessment.findings],
        "vulnerabilities": [v.to_dict() for v in assessment.vulnerabilities],
        "admitted": False,  # deny-by-default，需 confirm_tool_risk 确认分级后准入
    }
