"""CBOM 导出：CycloneDX 1.5（crypto-components 扩展）JSON 与 CSV。

参考 CycloneDX crypto bill of materials 社区扩展：components[].cryptoProperties，
把平台内部的 Finding/Component 模型映射到标准字段，便于交给合规工具链。
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .models import Finding

_PQ_TO_CYCLONE = {
    "broken-classical": "deprecated",
    "pq-vulnerable": "quantum-vulnerable",
    "pq-adjust": "quantum-adjust-required",
    "pq-safe": "quantum-safe",
}
_SEVERITY_RISK = {
    "critical": "critical", "high": "high", "medium": "medium", "info": "none",
}


def _bom_ref(system: str, f: Finding) -> str:
    return f"{system}:{f.algorithm}:{f.file_path}:{f.line}:{f.identity}"


def to_cyclonedx(inventories: list) -> dict:
    components = []
    seen = set()
    for inv in inventories:
        for f in inv.findings:
            ref = _bom_ref(inv.system, f)
            if ref in seen:
                continue
            seen.add(ref)
            crypto_props = {
                "assetType": f.asset_type.value,
                "algorithm": {
                    "primitive": f.category,
                    "variant": f.algorithm,
                },
                "implementation": {
                    "language": f.language,
                    "source": f.rule_id,
                    "confidence": f.confidence.value,
                },
                "quantumSafety": {
                    "assessment": _PQ_TO_CYCLONE.get(f.pq_status, "unknown"),
                    "note": f.pq_note,
                },
                "weakness": {
                    "isWeak": f.weak,
                    "severity": _SEVERITY_RISK[f.severity.value],
                },
                "occurrence": {
                    "file": f.file_path,
                    "line": f.line,
                    "rawUsage": f.variant_raw,
                    "context": f.context,
                },
            }
            if f.key_usage:
                crypto_props["keyProperties"] = {"usage": f.key_usage, **f.extra}
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f.algorithm,
                "version": "",
                "purl": f"pkg:generic/crypto-asset/{f.algorithm.lower()}?system={inv.system}",
                "cryptoProperties": crypto_props,
            })

    services = []
    for inv in inventories:
        if inv.readiness:
            services.append({
                "bom-ref": f"service:{inv.system}",
                "name": inv.system,
                "trustZone": "internal",
                "data": [{"name": "pq-readiness", "content": inv.readiness.level}],
                "cryptoProperties": {
                    "assetType": "service",
                    "quantumSafety": {
                        "assessment": inv.readiness.level,
                        "overallScore": inv.readiness.overall,
                        "classicScore": inv.readiness.classic_score,
                        "pqScore": inv.readiness.pq_score,
                    },
                },
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:cbom-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "crypto-inventory", "name": "crypto-asset-inventory",
                       "version": "1.0.0"}],
            "component": {"type": "application", "name": "enterprise-crypto-bom"},
            "properties": [
                {"name": "cbom:scope", "value": "source-code,configuration,certificates"},
            ],
        },
        "components": components,
        "services": services,
        "vulnerabilities": _vulnerabilities(inventories),
    }


def _vulnerabilities(inventories: list) -> list[dict]:
    """把弱用法映射成 CycloneDX vulnerabilities 段（内部编号，非 CVE）。"""
    out = []
    for inv in inventories:
        for f in inv.findings:
            if not f.weak and f.pq_status != "pq-vulnerable":
                continue
            vid = f"CRYPTO-{f.identity}"
            out.append({
                "id": vid,
                "source": {"name": "crypto-inventory-policy"},
                "ratings": [{
                    "severity": f.severity.value,
                    "method": "MANUAL",
                    "vector": f"CRYPTO/ALGORITHM/{f.algorithm}",
                }],
                "description": f"{f.algorithm} @ {f.file_path}:{f.line} — {f.pq_note}",
                "affects": [{"ref": _bom_ref(inv.system, f)}],
                "recommendation": f.pq_note,
            })
    return out


def to_csv(inventories: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["system", "asset_type", "language", "file", "line", "algorithm",
                "category", "raw_usage", "severity", "weak", "pq_status",
                "confidence", "rule_id", "key_usage", "pq_note", "context"])
    for inv in inventories:
        for f in inv.findings:
            w.writerow([inv.system, f.asset_type.value, f.language, f.file_path, f.line,
                        f.algorithm, f.category, f.variant_raw, f.severity.value,
                        int(f.weak), f.pq_status, f.confidence.value, f.rule_id,
                        f.key_usage, f.pq_note, f.context])
    return buf.getvalue()


def to_summary_csv(inventories: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["system", "algorithm", "category", "count", "severity", "weak",
                "pq_status", "example_file"])
    for inv in inventories:
        for c in inv.components:
            w.writerow([inv.system, c.algorithm, c.category, c.count,
                        c.severity.value, int(c.weak), c.pq_status,
                        c.examples[0]["file"] if c.examples else ""])
    return buf.getvalue()


def dump_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)
