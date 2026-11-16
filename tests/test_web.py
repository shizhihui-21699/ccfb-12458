"""Flask Web 应用端到端测试（测试客户端，无需起真实端口）。"""
from __future__ import annotations

import json

import pytest

from crypto_inventory.web import create_app


@pytest.fixture()
def client(repo, tmp_path):
    # repo 夹具生成 demo-system；让应用以其父目录为扫描根
    app = create_app(sample_root=repo.parent, db_path=tmp_path / "web.db")
    app.testing = True
    return app.test_client()


def test_pages_render(client):
    for path in ("/", "/findings", "/cbom", "/systems/demo-system"):
        assert client.get(path).status_code == 200


def test_overview_api(client):
    r = client.get("/api/overview")
    assert r.status_code == 200
    d = r.get_json()
    assert any(s["system"] == "demo-system" for s in d["systems"])
    assert d["totals"]["findings"] > 0


def test_system_api_and_404(client):
    r = client.get("/api/systems/demo-system")
    assert r.status_code == 200
    p = r.get_json()
    assert p["system"] == "demo-system"
    assert p["readiness"]["checklist"]
    assert client.get("/api/systems/ghost").status_code == 404


def test_findings_filters(client):
    all_r = client.get("/api/findings").get_json()
    weak_r = client.get("/api/findings?weak=1").get_json()
    crit_r = client.get("/api/findings?severity=critical").get_json()
    assert weak_r["count"] <= all_r["count"]
    assert all(f["weak"] for f in weak_r["findings"])
    assert all(f["severity"] == "critical" for f in crit_r["findings"])
    # 全文检索
    md5_r = client.get("/api/findings?q=md5").get_json()
    assert md5_r["count"] >= 1
    # 资产类型
    cfg_r = client.get("/api/findings?asset_type=config").get_json()
    assert all(f["asset_type"] == "config" for f in cfg_r["findings"])


def test_components_api(client):
    d = client.get("/api/components").get_json()
    algs = {c["algorithm"] for c in d["components"]}
    assert "MD5" in algs


def test_exports(client):
    r = client.get("/export/cyclonedx.json")
    assert r.status_code == 200
    bom = json.loads(r.data)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["components"]
    csv_r = client.get("/export/findings.csv")
    assert csv_r.status_code == 200
    assert b"algorithm" in csv_r.data
    sum_r = client.get("/export/components.csv")
    assert sum_r.status_code == 200


def test_scan_persists_and_blocks_traversal(client):
    r = client.post("/api/scan", json={"system": "demo-system"})
    assert r.status_code == 200
    assert r.get_json()["findings"] > 0
    bad = client.post("/api/scan", json={"system": "../../etc"})
    assert bad.status_code == 400
