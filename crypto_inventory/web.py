"""Flask Web 应用：盘点仪表盘、系统详情、发现查询、CBOM 导出与触发扫描。"""
from __future__ import annotations

import json
import os
from pathlib import Path

from flask import (Flask, Response, abort, jsonify, render_template, request,
                   send_file, url_for)

from .exporter import to_csv, to_cyclonedx, to_summary_csv, dump_json
from .inventory import scan_system, scan_workspace
from .store import Store

DEFAULT_SAMPLE_ROOT = Path(__file__).resolve().parents[1] / "samples"
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "inventory.db"


def create_app(sample_root: str | Path | None = None,
               db_path: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    root = Path(sample_root or os.environ.get("CRYPTO_SCAN_ROOT", DEFAULT_SAMPLE_ROOT))
    store = Store(db_path or os.environ.get("CRYPTO_DB", DEFAULT_DB))
    app.config["SCAN_ROOT"] = str(root)

    def _load_all() -> list[dict]:
        """优先读最近一次持久化快照；没有则即时扫描。"""
        payloads = store.all_latest_payloads()
        if payloads:
            return payloads
        return [inv.to_dict() for inv in scan_workspace(root)]

    def _load_system(system: str) -> dict:
        sid = store.latest_scan_id(system)
        if sid is not None:
            payload = store.get_scan_payload(sid)
            if payload:
                return payload
        target = root / system
        if not target.is_dir():
            abort(404, description=f"系统 {system} 不存在")
        return scan_system(target, system).to_dict()

    # ------------------------------------------------ 页面
    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", active="dashboard")

    @app.get("/systems/<system>")
    def system_detail(system: str):
        return render_template("system.html", system=system, active="systems")

    @app.get("/findings")
    def findings_page():
        return render_template("findings.html", active="findings")

    @app.get("/cbom")
    def cbom_page():
        return render_template("cbom.html", active="cbom")

    # ------------------------------------------------ API
    @app.get("/api/overview")
    def api_overview():
        payloads = _load_all()
        systems = []
        totals = {"findings": 0, "critical": 0, "high": 0, "medium": 0, "info": 0,
                  "weak": 0, "pq_vulnerable": 0, "pq_safe_asym": 0}
        for p in payloads:
            r = p["readiness"]
            systems.append({
                "system": p["system"], "root": p["root"],
                "finding_count": len(p["findings"]),
                "overall": r["overall"], "level": r["level"], "level_cn": r["level_cn"],
                "classic_score": r["classic_score"], "pq_score": r["pq_score"],
                "by_severity": r["by_severity"], "by_pq_status": r["by_pq_status"],
                "by_asset_type": r["by_asset_type"],
            })
            totals["findings"] += len(p["findings"])
            for sev in ("critical", "high", "medium", "info"):
                totals[sev] += r["by_severity"].get(sev, 0)
            totals["weak"] += sum(1 for f in p["findings"] if f["weak"])
            totals["pq_vulnerable"] += r["by_pq_status"].get("pq-vulnerable", 0)
            totals["pq_safe_asym"] += sum(
                1 for f in p["findings"]
                if f["pq_status"] == "pq-safe" and f["category"] in ("asymmetric", "kex"))
        systems.sort(key=lambda s: s["overall"])
        return jsonify({"systems": systems, "totals": totals})

    @app.get("/api/systems/<system>")
    def api_system(system: str):
        return jsonify(_load_system(system))

    @app.get("/api/findings")
    def api_findings():
        sev = request.args.get("severity")
        pq = request.args.get("pq_status")
        asset = request.args.get("asset_type")
        weak_only = request.args.get("weak") == "1"
        q = (request.args.get("q") or "").lower()
        system = request.args.get("system")
        out = []
        for p in _load_all():
            if system and p["system"] != system:
                continue
            for f in p["findings"]:
                if sev and f["severity"] != sev:
                    continue
                if pq and f["pq_status"] != pq:
                    continue
                if asset and f["asset_type"] != asset:
                    continue
                if weak_only and not f["weak"]:
                    continue
                if q and q not in (f["algorithm"] + " " + f["file_path"] + " " +
                                   f["variant_raw"] + " " + f["context"]).lower():
                    continue
                row = dict(f)
                row["system"] = p["system"]
                out.append(row)
        out.sort(key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "info": 3}[f["severity"]],
            f["system"], f["file_path"], f["line"]))
        return jsonify({"count": len(out), "findings": out})

    @app.get("/api/components")
    def api_components():
        rows = []
        for p in _load_all():
            for c in p["components"]:
                row = dict(c)
                row["system"] = p["system"]
                rows.append(row)
        return jsonify({"components": rows})

    # ------------------------------------------------ 导出
    def _inventories():
        from .inventory import SystemInventory, SystemReadiness
        from .models import Finding, Component, AssetType, Severity, Confidence
        # 由持久化 payload 重建轻量对象供 exporter 使用
        class _Inv:
            def __init__(self, p):
                self.system = p["system"]
                self.root = p["root"]
                self.readiness = type("R", (), p["readiness"])
                self.findings = [_rebuild_finding(self.system, f) for f in p["findings"]]
                self.components = []
        return [_Inv(p) for p in _load_all()]

    @app.get("/export/cyclonedx.json")
    def export_cdx():
        bom = to_cyclonedx(_inventories())
        return Response(dump_json(bom), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=cbom-cyclonedx.json"})

    @app.get("/export/findings.csv")
    def export_csv():
        return Response(to_csv(_inventories()), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=crypto-findings.csv"})

    @app.get("/export/components.csv")
    def export_summary_csv():
        return Response(to_summary_csv(_inventories()), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=crypto-components.csv"})

    # ------------------------------------------------ 触发扫描
    @app.post("/api/scan")
    def api_scan():
        target = (request.get_json(silent=True) or {}).get("system")
        if target:
            t = (root / target).resolve()
            if not str(t).startswith(str(root.resolve())) or not t.is_dir():
                abort(400, description="非法系统路径")
            inv = scan_system(t, target)
        else:
            inventories = scan_workspace(root)
            for inv in inventories:
                store.save_scan(inv)
            return jsonify({"scanned": [i.system for i in inventories]})
        sid = store.save_scan(inv)
        return jsonify({"scanned": [inv.system], "scan_id": sid,
                        "findings": len(inv.findings)})

    return app


def _rebuild_finding(system: str, d: dict):
    from .models import AssetType, Confidence, Finding, Severity
    return Finding(
        system=system, asset_type=AssetType(d["asset_type"]),
        language=d["language"], file_path=d["file_path"], line=d["line"],
        algorithm=d["algorithm"], category=d["category"],
        variant_raw=d["variant_raw"], rule_id=d["rule_id"],
        confidence=Confidence(d["confidence"]), severity=Severity(d["severity"]),
        weak=d["weak"], pq_status=d["pq_status"], pq_note=d["pq_note"],
        context=d.get("context", ""), key_usage=d.get("key_usage", ""),
        extra=d.get("extra", {}),
    )
