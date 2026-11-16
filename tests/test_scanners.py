"""三类扫描器的识别能力测试。"""
from __future__ import annotations

from collections import Counter

from crypto_inventory.inventory import scan_system
from crypto_inventory.models import AssetType
from crypto_inventory.scanners.code_scanner import scan_file
from crypto_inventory.scanners.config_scanner import decode_ssh_alg, decode_tls_suite


def _algs(inv, **filters):
    out = []
    for f in inv.findings:
        if all(getattr(f, k) == v for k, v in filters.items()):
            out.append(f.algorithm)
    return out


# ------------------------------------------------- 代码：同一算法多种写法

def test_python_md5_variants_normalize(repo):
    inv = scan_system(repo, "demo-system")
    md5 = [f for f in inv.findings
           if f.algorithm == "MD5" and f.file_path.endswith("a.py")]
    # hashlib.md5 + hashlib.new("sha1") 不算；md5 直接调用 1 处
    assert len(md5) >= 1
    assert all(f.confidence.value in ("high", "medium") for f in md5)


def test_python_ast_detects_ecb_and_jwt_none(repo):
    inv = scan_system(repo, "demo-system")
    names = _algs(inv)
    assert "ECB-MODE" in names
    assert "JWT-NONE" in names
    assert "INSECURE-RNG" in names


def test_comment_stripped(repo):
    inv = scan_system(repo, "demo-system")
    comment_hits = [f for f in inv.findings
                    if f.file_path.endswith("a.py") and f.line == 12]
    assert comment_hits == []


def test_java_transformation_strings(repo):
    inv = scan_system(repo, "demo-system")
    java = [f for f in inv.findings if f.file_path.endswith("B.java")]
    names = {f.algorithm for f in java}
    assert "MD5" in names
    assert "3DES" in names
    assert "ECB-MODE" in names
    assert "AES-128-CBC" in names


def test_go_and_js_and_c(repo):
    inv = scan_system(repo, "demo-system")
    by_file: dict[str, set] = {}
    for f in inv.findings:
        by_file.setdefault(f.file_path, set()).add(f.algorithm)
    assert {"MD5", "INSECURE-RNG"} <= by_file["go/c.go"]
    assert {"SHA-1", "3DES", "INSECURE-RNG"} <= by_file["js/d.js"]
    c_names = by_file["c/e.c"]
    assert "MD5" in c_names and "INSECURE-RNG" in c_names
    assert any("ECB" in n for n in c_names)


def test_dedup_same_line_algorithm(repo):
    inv = scan_system(repo, "demo-system")
    # 同一行同一算法只出现一次
    keys = [(f.file_path, f.line, f.algorithm) for f in inv.findings]
    assert len(keys) == len(set(keys))


def test_higher_confidence_wins(repo):
    findings = scan_file("demo-system", repo, repo / "go" / "c.go")
    md5 = [f for f in findings if f.algorithm == "MD5"]
    assert md5 and all(f.confidence.value != "low" for f in md5)


# ------------------------------------------------- 配置：TLS/SSH 套件

def test_tls_suite_decoder_iana():
    comp = dict((c, w) for c, _, w in decode_tls_suite("TLS_RSA_WITH_AES_128_CBC_SHA"))
    assert comp["AES-128-CBC"] is True
    assert comp["SHA-1"] is True
    assert "RSA" in comp


def test_tls_suite_decoder_openssl_weak():
    comp = dict((c, w) for c, _, w in decode_tls_suite("RC4-MD5"))
    assert comp["RC4"] is True and comp["MD5"] is True
    comp = dict((c, w) for c, _, w in decode_tls_suite("ECDHE-RSA-DES-CBC3-SHA"))
    assert comp["3DES"] is True


def test_tls13_suite():
    comp = decode_tls_suite("TLS_AES_256_GCM_SHA384")
    names = [c for c, _, _ in comp]
    assert "AES-256-GCM" in names and "TLS1.3" in names


def test_ssh_decoder():
    assert decode_ssh_alg("diffie-hellman-group1-sha1")[0] == "DH-1024"
    assert decode_ssh_alg("ssh-dss")[2] is True
    assert decode_ssh_alg("chacha20-poly1305@openssh.com")[0] == "CHACHA20-POLY1305"
    assert "ML-KEM" in decode_ssh_alg("mlkem768x25519-sha256")[0]


def test_config_scan_end_to_end(repo):
    inv = scan_system(repo, "demo-system")
    cfg = [f for f in inv.findings if f.asset_type == AssetType.CONFIG]
    names = {f.algorithm for f in cfg}
    # 协议版本
    assert "TLS1.0" in names and "TLS1.1" in names
    # 弱套件组件
    assert {"RC4", "MD5", "3DES", "AES-128-CBC", "HMAC-MD5", "DH-1024", "DSA-1024"} <= names
    # PQ 混合组
    assert any("ML-KEM" in n for n in names)
    # yaml 块列表被识别
    yaml_hits = [f for f in cfg if f.file_path.endswith("app.yaml")]
    assert {"RSA-512", "RC4"} <= {f.algorithm for f in yaml_hits}


# ------------------------------------------------- 聚合与评分

def test_readiness_and_components(repo):
    inv = scan_system(repo, "demo-system")
    r = inv.readiness
    assert 0 <= r.overall <= 100
    assert r.by_severity["critical"] > 0
    assert r.level in ("exposed", "planning", "progressing", "ready")
    # 组件聚合
    comp_algs = {c.algorithm for c in inv.components}
    assert "MD5" in comp_algs and "ECB-MODE" in comp_algs
    md5_comp = next(c for c in inv.components if c.algorithm == "MD5")
    assert md5_comp.count >= 3  # 多语言多处
    # 检查清单 10 项齐全
    assert len(r.checklist) == 10
    assert {c["state"] for c in r.checklist} <= {"done", "inprogress", "todo"}


def test_asset_type_coverage(repo):
    inv = scan_system(repo, "demo-system")
    types = Counter(f.asset_type.value for f in inv.findings)
    assert types["code"] > 0 and types["config"] > 0
