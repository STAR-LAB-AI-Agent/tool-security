"""工具安全评估引擎：把 bandit / pip-audit 化为安全控制机制的一部分。

职责定位（区别于普通业务工具）：
- bandit、pip-audit 不是「被管控的业务工具」，而是「安全控制机制的评估引擎」。
- 在工具「接入 / 准入」阶段，用它们自动产出安全决策依据：
    * bandit：扫描工具源码，检测命令执行、危险 API、硬编码密钥等，自动划分风险等级；
    * pip-audit：扫描工具依赖，检测已知 CVE，自动判定是否准入工具白名单。

评估结果写入 Policy.tool_policies（M1 已预留 risk / allowed 两个字段），
随后由 ToolGateway 在运行期消费，完成「开源工具参与安全决策」的闭环。
"""
from __future__ import annotations

import inspect
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import tools as _tools_module
from .policy_store import ToolPolicy
from .registry import TOOL_REGISTRY
from .security import RiskLevel, SecurityError

_BANDIT_TIMEOUT = 30
_PIP_AUDIT_TIMEOUT = 90


def severity_to_risk(severity: str) -> RiskLevel:
    """把 bandit 的 severity（low/medium/high）映射为 RiskLevel。"""
    return RiskLevel(str(severity).strip().lower())


# --------------------------------------------------------------------------- 数据模型
@dataclass
class BanditFinding:
    test_id: str
    severity: str
    line: int
    text: str
    filename: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "severity": self.severity,
            "line": self.line,
            "text": self.text,
            "filename": self.filename,
        }


@dataclass
class DependencyVuln:
    package: str
    version: str
    vuln_id: str
    aliases: List[str]
    fix_versions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "id": self.vuln_id,
            "aliases": self.aliases,
            "fix_versions": self.fix_versions,
        }


@dataclass
class ToolAssessment:
    tool_name: str
    risk: RiskLevel
    allowed: bool
    findings: List[BanditFinding] = field(default_factory=list)
    vulnerabilities: List[DependencyVuln] = field(default_factory=list)
    pip_audit_status: str = "no_deps"  # ok / no_deps / skipped_offline

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "risk": self.risk.value,
            "allowed": self.allowed,
            "bandit_findings": [f.to_dict() for f in self.findings],
            "pip_audit_status": self.pip_audit_status,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


# --------------------------------------------------------------------------- bandit
def run_bandit(source: Path) -> List[BanditFinding]:
    """调用 bandit 扫描单个源码文件，返回命中列表（离线可用，无需联网）。"""
    p = Path(source)
    if not p.is_file():
        raise SecurityError(f"待评估源码不存在：{p}")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", str(p)],
            capture_output=True, text=True, timeout=_BANDIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise SecurityError(f"bandit 扫描超时（>{_BANDIT_TIMEOUT}s）") from e

    # bandit 命中漏洞时退出码为 1，属正常业务结果；只有 stdout 无法解析才视为失败。
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        raise SecurityError(f"bandit 执行失败：{proc.stderr.strip() or e}") from e

    findings: List[BanditFinding] = []
    for item in data.get("results", []):
        findings.append(BanditFinding(
            test_id=str(item.get("test_id", "")),
            severity=str(item.get("issue_severity", "low")),
            line=int(item.get("line_number", 0)),
            text=str(item.get("issue_text", "")),
            filename=str(item.get("filename", p)),
        ))
    return findings


def _max_severity_risk(findings: List[BanditFinding]) -> RiskLevel:
    """命中列表的最高严重级别映射为风险；无命中视为 LOW。"""
    if not findings:
        return RiskLevel.LOW
    return max((severity_to_risk(f.severity) for f in findings), key=lambda r: r.rank)


# --------------------------------------------------------------------------- pip-audit
def _parse_pip_audit_json(raw: str) -> Tuple[str, List[DependencyVuln]]:
    """解析 pip-audit 的 JSON 输出为 (status, 漏洞列表)。纯函数，便于单测。"""
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return "skipped_offline", []
    if "dependencies" not in data:
        return "skipped_offline", []
    vulns: List[DependencyVuln] = []
    for dep in data.get("dependencies", []):
        for v in (dep.get("vulns") or []):
            vulns.append(DependencyVuln(
                package=str(dep.get("name", "?")),
                version=str(dep.get("version", "")),
                vuln_id=str(v.get("id", "")),
                aliases=[str(a) for a in (v.get("aliases") or [])],
                fix_versions=[str(f) for f in (v.get("fix_versions") or [])],
            ))
    return "ok", vulns


def audit_dependencies(requirement_path: Optional[Path]) -> Tuple[str, List[DependencyVuln]]:
    """调用 pip-audit 扫描依赖漏洞；离线 / 失败时降级为 skipped_offline（跳过而非阻断）。"""
    if requirement_path is None or not Path(requirement_path).is_file():
        return "no_deps", []
    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "pip_audit", "-r", str(requirement_path),
                "-f", "json", "--disable-pip", "--progress-spinner", "off",
            ],
            capture_output=True, text=True, timeout=_PIP_AUDIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "skipped_offline", []
    except OSError:
        return "skipped_offline", []
    # 无论退出码（有漏洞时为 1），只要 stdout 是合法 JSON 就解析；否则视为离线/失败降级。
    return _parse_pip_audit_json(proc.stdout)


# --------------------------------------------------------------------------- 组合评估
def assess_tool_source(
    tool_name: str,
    source_path: Path,
    requirement_path: Optional[Path] = None,
    base_risk: RiskLevel = RiskLevel.LOW,
) -> ToolAssessment:
    """评估一个工具的源码与依赖，产出风险等级与白名单准入建议。

    - 风险等级 = max(业务基础风险, bandit 命中风险)：bandit 只上调、不降级，
      避免「写/删文件等业务副作用」被静态扫描误判为无风险。
    - allowed = 依赖无已知漏洞（pip-audit ok 且无漏洞）；离线 / 无依赖时放行（降级）。
    """
    findings = run_bandit(Path(source_path))
    bandit_risk = _max_severity_risk(findings)
    risk = base_risk if base_risk.rank >= bandit_risk.rank else bandit_risk

    status, vulns = audit_dependencies(requirement_path)
    allowed = not (status == "ok" and vulns)

    return ToolAssessment(
        tool_name=tool_name,
        risk=risk,
        allowed=allowed,
        findings=findings,
        vulnerabilities=vulns,
        pip_audit_status=status,
    )


def assess_builtin_tools() -> Dict[str, ToolPolicy]:
    """对内置工具做函数级 bandit 评估：按行号把命中归属到具体工具函数。

    模块级命中（如 import subprocess、常量字典）不属于任何函数，会被忽略。
    """
    source_file = Path(_tools_module.__file__)
    findings = run_bandit(source_file)
    result: Dict[str, ToolPolicy] = {}
    for name, tool in TOOL_REGISTRY.items():
        try:
            lines, start = inspect.getsourcelines(tool.func)
        except (OSError, TypeError):
            continue
        end = start + len(lines) - 1
        func_findings = [f for f in findings if start <= f.line <= end]
        bandit_risk = _max_severity_risk(func_findings)
        # 风险等级取更严格者：bandit 只上调，基础风险（写/删/命令）不会被降级。
        effective = tool.risk if tool.risk.rank >= bandit_risk.rank else bandit_risk
        result[name] = ToolPolicy(allowed=True, risk=effective)
    return result
