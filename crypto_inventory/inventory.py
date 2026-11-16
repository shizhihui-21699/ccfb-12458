"""盘点编排：扫描一个系统仓库并聚合为密码物料清单 (CBOM)。"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path

from .models import AssetType, Component, Finding, Severity
from .readiness import SystemReadiness, evaluate
from .scanners import scan_certificates, scan_code, scan_config


@dataclass
class SystemInventory:
    system: str
    root: str
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    readiness: SystemReadiness | None = None

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "root": self.root,
            "findings": [f.to_dict() for f in self.findings],
            "components": [c.to_dict() for c in self.components],
            "readiness": dataclasses.asdict(self.readiness) if self.readiness else None,
        }


def _aggregate(findings: list[Finding]) -> list[Component]:
    table: dict[str, Component] = {}
    for f in findings:
        comp = table.get(f.algorithm)
        if comp is None:
            comp = Component(
                algorithm=f.algorithm, category=f.category,
                pq_status=f.pq_status, severity=f.severity, weak=f.weak, count=0,
            )
            table[f.algorithm] = comp
        comp.count += 1
        comp.systems.add(f.system)
        if len(comp.examples) < 5:
            comp.examples.append({
                "system": f.system, "file": f.file_path,
                "line": str(f.line), "raw": f.variant_raw,
            })
        # 严重度取最高
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}
        if order[f.severity] < order[comp.severity]:
            comp.severity = f.severity
            comp.weak = f.weak
    return sorted(table.values(), key=lambda c: (
        {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.INFO: 3}[c.severity],
        c.algorithm))


def scan_system(root: str | Path, system: str | None = None) -> SystemInventory:
    root = Path(root).resolve()
    system = system or root.name
    inv = SystemInventory(system=system, root=str(root))
    inv.findings.extend(scan_code(root, system))
    inv.findings.extend(scan_config(root, system))
    inv.findings.extend(scan_certificates(root, system))
    # 全局去重（同文件同行同算法）
    uniq: dict[str, Finding] = {}
    for f in inv.findings:
        uniq.setdefault(f.identity, f)
    inv.findings = sorted(uniq.values(), key=lambda f: (
        f.asset_type.value, f.file_path, f.line, f.algorithm))
    inv.components = _aggregate(inv.findings)
    inv.readiness = evaluate(system, inv.findings)
    return inv


def scan_workspace(workspace_root: str | Path) -> list[SystemInventory]:
    """扫描工作区下每个子目录（每个子目录视为一个系统）。"""
    workspace_root = Path(workspace_root)
    out: list[SystemInventory] = []
    for child in sorted(workspace_root.iterdir()):
        if child.is_dir() and not child.name.startswith((".", "_")):
            out.append(scan_system(child, child.name))
    return out
