"""CBOM 导出与存储测试。"""
from __future__ import annotations

import csv
import io
import json

from crypto_inventory.exporter import to_csv, to_cyclonedx, to_summary_csv
from crypto_inventory.inventory import scan_system
from crypto_inventory.store import Store


def test_cyclonedx_structure(repo):
    inv = scan_system(repo, "demo-system")
    bom = to_cyclonedx([inv])
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["components"], "至少应有一个密码组件"
    for c in bom["components"]:
        cp = c["cryptoProperties"]
        assert cp["algorithm"]["variant"]
        assert cp["quantumSafety"]["assessment"] in (
            "deprecated", "quantum-vulnerable", "quantum-adjust-required", "quantum-safe")
    assert bom["vulnerabilities"], "弱用法应映射为 vulnerabilities"
    # JSON 可序列化
    json.dumps(bom, ensure_ascii=False)


def test_csv_roundtrip(repo):
    inv = scan_system(repo, "demo-system")
    text = to_csv([inv])
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(inv.findings)
    assert {"algorithm", "pq_status", "severity", "file"} <= set(rows[0].keys())


def test_summary_csv(repo):
    inv = scan_system(repo, "demo-system")
    text = to_summary_csv([inv])
    rows = list(csv.DictReader(io.StringIO(text)))
    md5 = next(r for r in rows if r["algorithm"] == "MD5")
    assert int(md5["count"]) >= 1


def test_store_persistence(repo, tmp_path):
    inv = scan_system(repo, "demo-system")
    store = Store(tmp_path / "inv.db")
    sid = store.save_scan(inv)
    assert sid > 0
    scans = store.list_scans()
    assert scans and scans[0]["system"] == "demo-system"
    payload = store.get_scan_payload(sid)
    assert payload["system"] == "demo-system"
    assert len(payload["findings"]) == len(inv.findings)
    assert store.latest_scan_id("demo-system") == sid
