"""证书/密钥扫描器测试：用 cryptography 现场生成各种材料。"""
from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from crypto_inventory.inventory import scan_system

NOW = datetime.datetime.now(datetime.timezone.utc)


def _cn(name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])


def _cert(key, cn, issuer_key, hash_alg, days=100):
    return (x509.CertificateBuilder()
            .subject_name(_cn(cn)).issuer_name(_cn(cn))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=days))
            .sign(issuer_key, hash_alg))


@pytest.fixture()
def cert_repo(tmp_path: Path) -> Path:
    root = tmp_path / "cert-system"
    d = root / "pki"
    d.mkdir(parents=True)

    rsa1024 = rsa.generate_private_key(65537, 1024)
    rsa2048 = rsa.generate_private_key(65537, 2048)
    ec256 = ec.generate_private_key(ec.SECP256R1())
    ed = ed25519.Ed25519PrivateKey.generate()

    # RSA2048 + SHA256 正常证书
    c1 = _cert(rsa2048, "ok.example.com", rsa2048, hashes.SHA256())
    (d / "ok.crt").write_bytes(c1.public_bytes(serialization.Encoding.PEM))
    # 未加密 RSA1024 私钥
    (d / "weak.key").write_bytes(rsa1024.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    # 弱口令加密私钥
    (d / "enc.key").write_bytes(rsa2048.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"password")))
    # EC 证书
    c2 = _cert(ec256, "ec.example.com", ec256, hashes.SHA256())
    (d / "ec.crt").write_bytes(c2.public_bytes(serialization.Encoding.PEM))
    # OpenSSH 公钥
    (d / "ed.pub").write_bytes(ed.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))
    # OpenSSH 私钥
    (d / "ed.key").write_bytes(ed.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()))
    # PKCS#12 弱口令
    p12 = pkcs12.serialize_key_and_certificates(
        b"t", rsa2048, c1, None, serialization.BestAvailableEncryption(b"changeit"))
    (d / "store.p12").write_bytes(p12)
    # 过期证书
    expired = (x509.CertificateBuilder()
               .subject_name(_cn("old")).issuer_name(_cn("old"))
               .public_key(rsa2048.public_key()).serial_number(2)
               .not_valid_before(NOW - datetime.timedelta(days=400))
               .not_valid_after(NOW - datetime.timedelta(days=10))
               .sign(rsa2048, hashes.SHA256()))
    (d / "expired.crt").write_bytes(expired.public_bytes(serialization.Encoding.PEM))
    # 损坏文件容错
    (d / "broken.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nxxx\n")
    return root


def test_cert_algorithms_and_lengths(cert_repo):
    inv = scan_system(cert_repo, "cert-system")
    algs = {f.algorithm for f in inv.findings}
    assert "RSA-2048" in algs
    assert "RSA-1024" in algs
    assert "ECDSA-P256" in algs
    assert "ED25519" in algs
    rsa1024 = next(f for f in inv.findings if f.algorithm == "RSA-1024")
    assert rsa1024.severity.value == "critical"
    assert rsa1024.pq_status == "broken-classical"


def test_signature_hash_detected(cert_repo):
    inv = scan_system(cert_repo)
    hashes_found = {f.algorithm for f in inv.findings if f.key_usage == "certificate-signature-hash"}
    assert "SHA-256" in hashes_found


def test_weak_password_flags(cert_repo):
    inv = scan_system(cert_repo)
    pws = [f for f in inv.findings if f.algorithm == "WEAK-KEY-PASSWORD"]
    assert len(pws) == 2  # enc.key + store.p12
    assert all(f.severity.value == "critical" for f in pws)


def test_expired_cert(cert_repo):
    inv = scan_system(cert_repo)
    assert any(f.algorithm == "EXPIRED-CERT" for f in inv.findings)


def test_corrupt_pem_does_not_crash(cert_repo):
    inv = scan_system(cert_repo)  # 不抛异常即可
    assert inv.readiness is not None


def test_pkcs12_contents(cert_repo):
    inv = scan_system(cert_repo)
    p12_hits = [f for f in inv.findings if f.file_path.endswith("store.p12")]
    assert any(f.algorithm in ("RSA-2048", "SHA-256") for f in p12_hits)
    assert any(f.algorithm == "WEAK-KEY-PASSWORD" and f.language == "pkcs12" for f in p12_hits)
