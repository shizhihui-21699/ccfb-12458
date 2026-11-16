"""证书与密钥文件扫描器。

覆盖：
- X.509 PEM/DER 证书（.crt/.cer/.pem）：签名算法、主体密钥算法与位长、有效期、SAN
- PEM 私钥（RSA/DSA/EC/Ed25519/Ed448/X25519/X448，含 PKCS#8 加密私钥）
- OpenSSH 公钥（.pub，ssh-rsa / ecdsa-sha2-* / ssh-ed25519 / ml-* ）
- OpenSSH 私钥（BEGIN OPENSSH PRIVATE KEY）
- PKCS#12（.p12/.pfx，尝试空密码与常见弱密码）
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed25519, ed448, rsa, x25519, x448,
)
from cryptography.x509.oid import NameOID

from ..models import AssetType, Confidence, Finding, Severity
from ..rules.catalog import AlgInfo, classify

CERT_EXT = {".crt", ".cer", ".pem", ".der", ".cert"}
KEY_EXT = {".key", ".pem"}
PUB_EXT = {".pub"}
PKCS12_EXT = {".p12", ".pfx"}
PEM_MARKER_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
WEAK_P12_PASSWORDS = [b"", b"changeit", b"password", b"123456", b"insecure"]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}

# 证书签名 OID → (非对称基名, 哈希名)
_SIG_OID = {
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.3.14.3.2.29": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.10": ("RSA", "SHA-256"),   # RSASSA-PSS
    "2.16.840.1.101.3.4.3.2": ("ECDSA", "SHA-256"),
    "2.16.840.1.101.3.4.3.3": ("ECDSA", "SHA-384"),
    "2.16.840.1.101.3.4.3.4": ("ECDSA", "SHA-512"),
    "1.3.101.112": ("ED25519", None),
    "1.3.101.113": ("ED448", None),
    "2.16.840.1.101.3.4.3.5": ("ML-DSA-65", "SHA-256"),
}


def _classify_key(base: str, bits: int | None):
    """RSA/DSA 拼位长；EC/Ed/X 名字本身已含曲线。"""
    if base in ("RSA", "DSA", "DH") and bits:
        return classify(f"{base}-{bits}")
    return classify(base)


def _f(system: str, rel: str, raw: str, result: tuple[str, AlgInfo],
       usage: str, extra: dict, confidence: Confidence = Confidence.HIGH) -> Finding:
    canon, info = result
    return Finding(
        system=system, asset_type=AssetType.CERT, language="x509",
        file_path=rel, line=0, algorithm=canon, category=info.category,
        variant_raw=raw[:200], rule_id="cert-parse", confidence=confidence,
        severity=Severity(info.severity), weak=info.weak,
        pq_status=info.pq_status, pq_note=info.pq_note,
        key_usage=usage, extra=extra,
    )


_EC_CURVE_NAMES = {
    "secp192r1": "P-192", "secp224r1": "P-224", "secp256r1": "P-256",
    "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "SECP256K1",
}


def _key_algorithm(pub) -> tuple[str, int | None]:
    """从公钥对象得到 (基础算法名, 位长)。"""
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = _EC_CURVE_NAMES.get(pub.curve.name, pub.curve.name.upper())
        return f"ECDSA-{curve}", pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ED25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ED448", 456
    if isinstance(pub, x25519.X25519PublicKey):
        return "X25519", 256
    if isinstance(pub, x448.X448PublicKey):
        return "X448", 448
    return type(pub).__name__, None


def _scan_x509(system: str, rel: str, data: bytes, sink: list[Finding]) -> None:
    try:
        if b"-----BEGIN" in data:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except Exception:
        return

    base, bits = _key_algorithm(cert.public_key())
    res = _classify_key(base, bits)
    if res:
        sink.append(_f(system, rel, f"{base} {bits or ''}bit 主体公钥", res,
                       "certificate-subject-key",
                       {"bits": bits, "subject": cert.subject.rfc4514_string()[:200],
                        "not_after": cert.not_valid_after_utc.isoformat()}))
    # 签名算法（非对称 + 哈希 两条物料）
    oid = cert.signature_algorithm_oid.dotted_string
    sig = _SIG_OID.get(oid)
    sig_name = cert.signature_algorithm_oid._name  # cryptography 自带名
    if sig:
        asym, h = sig
        asym_res = _classify_key(asym, bits) if asym in ("RSA", "DSA") else classify(asym)
        if asym_res:
            sink.append(_f(system, rel, f"签名算法 {sig_name}", asym_res,
                           "certificate-signature",
                           {"signature_oid": oid, "subject": cert.subject.rfc4514_string()[:200]}))
        if h:
            h_res = classify(h)
            if h_res:
                sink.append(_f(system, rel, f"签名哈希 {h}", h_res,
                               "certificate-signature-hash",
                               {"signature_oid": oid}))
    else:
        # OID 未知时尝试从名字里抽哈希
        for hname in ("MD5", "SHA1", "SHA256", "SHA384", "SHA512"):
            if hname.lower().replace("sha1", "sha-1") in sig_name.lower() or hname in sig_name:
                r = classify("SHA-1" if hname == "SHA1" else hname)
                if r:
                    sink.append(_f(system, rel, f"签名哈希 {sig_name}", r,
                                   "certificate-signature-hash", {"signature_oid": oid},
                                   Confidence.MEDIUM))
    # 有效期检查（过期/有效期过长作为附加弱用法提示）
    now = datetime.now(timezone.utc)
    extra = {"not_after": cert.not_valid_after_utc.isoformat(),
             "not_before": cert.not_valid_before_utc.isoformat()}
    if cert.not_valid_after_utc < now:
        sink.append(Finding(
            system=system, asset_type=AssetType.CERT, language="x509",
            file_path=rel, line=0, algorithm="EXPIRED-CERT", category="lifecycle",
            variant_raw=sig_name, rule_id="cert-lifecycle",
            confidence=Confidence.HIGH, severity=Severity.MEDIUM, weak=True,
            pq_status="broken-classical", pq_note="证书已过期，需立即更换并借机完成算法升级",
            key_usage="lifecycle", extra=extra))
    else:
        days = (cert.not_valid_after_utc - now).days
        if days > 398:
            sink.append(Finding(
                system=system, asset_type=AssetType.CERT, language="x509",
                file_path=rel, line=0, algorithm="LONG-LIVED-CERT", category="lifecycle",
                variant_raw=f"剩余 {days} 天", rule_id="cert-lifecycle",
                confidence=Confidence.HIGH, severity=Severity.INFO, weak=False,
                pq_status="pq-adjust",
                pq_note="证书有效期超过 398 天基线，缩短生命周期便于 PQ 迁移轮换",
                key_usage="lifecycle", extra={**extra, "days_remaining": days}))
    # SAN
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        extra["san"] = san.value.get_values_for_type(x509.DNSName)[:10]
    except x509.ExtensionNotFound:
        pass


def _scan_private_key(system: str, rel: str, data: bytes, marker: str,
                      sink: list[Finding]) -> None:
    encrypted = b"ENCRYPTED" in marker.encode() or b"Proc-Type: 4,ENCRYPTED" in data[:512]
    try:
        if "OPENSSH PRIVATE KEY" in marker:
            key = serialization.load_ssh_private_key(data, password=None)
        elif encrypted:
            # 加密 PKCS#8：尝试常见弱密码，失败则只报文件存在
            key = None
            for pw in WEAK_P12_PASSWORDS:
                try:
                    key = serialization.load_pem_private_key(data, password=pw)
                    if pw:
                        sink.append(Finding(
                            system=system, asset_type=AssetType.CERT, language="pem-key",
                            file_path=rel, line=0, algorithm="WEAK-KEY-PASSWORD",
                            category="key-protection", variant_raw=pw.decode(errors="replace"),
                            rule_id="key-protection", confidence=Confidence.HIGH,
                            severity=Severity.CRITICAL, weak=True,
                            pq_status="broken-classical",
                            pq_note="私钥使用弱口令加密，需更换为强口令/HSM/KMS",
                            key_usage="private-key-protection"))
                    break
                except (TypeError, ValueError):
                    continue
        else:
            key = serialization.load_pem_private_key(data, password=None)
    except Exception:
        # 无法解密：仍记录一个待人工确认条目
        sink.append(Finding(
            system=system, asset_type=AssetType.CERT, language="pem-key",
            file_path=rel, line=0, algorithm="ENCRYPTED-KEY-UNKNOWN",
            category="key-protection", variant_raw=marker, rule_id="cert-parse",
            confidence=Confidence.LOW, severity=Severity.INFO, weak=False,
            pq_status="pq-vulnerable",
            pq_note="加密私钥无法离线解析，需在密钥管理系统中核对其算法",
            key_usage="private-key"))
        return
    if key is None:
        return
    base, bits = _key_algorithm(key.public_key())
    res = _classify_key(base, bits)
    if res:
        sink.append(_f(system, rel, f"{marker} ({base} {bits or ''}bit)", res,
                       "private-key", {"bits": bits, "encrypted_at_rest": encrypted}))


def _scan_ssh_public(system: str, rel: str, data: bytes, sink: list[Finding]) -> None:
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith(b"#"):
            continue
        try:
            parts = line.split()
            key_type = parts[0].decode()
            pub = serialization.load_ssh_public_key(line)
        except Exception:
            continue
        base, bits = _key_algorithm(pub)
        raw = f"{key_type} ({base} {bits or ''}bit)"
        # ssh-rsa 位长无法从公钥类型得知，对象里有
        res = _classify_key(base, bits)
        if res:
            sink.append(_f(system, rel, raw, res, "ssh-public-key",
                           {"ssh_key_type": key_type, "bits": bits},
                           Confidence.HIGH))


def _scan_pkcs12(system: str, rel: str, data: bytes, sink: list[Finding]) -> None:
    loaded = None
    used_pw = None
    for pw in WEAK_P12_PASSWORDS:
        try:
            loaded = pkcs12.load_key_and_certificates(data, pw)
            used_pw = pw
            break
        except Exception:
            continue
    if not loaded:
        sink.append(Finding(
            system=system, asset_type=AssetType.CERT, language="pkcs12",
            file_path=rel, line=0, algorithm="PKCS12-UNKNOWN", category="key-protection",
            variant_raw=rel, rule_id="cert-parse", confidence=Confidence.LOW,
            severity=Severity.INFO, weak=False, pq_status="pq-vulnerable",
            pq_note="PKCS#12 无法离线解析，需在密钥管理系统中核对",
            key_usage="keystore"))
        return
    if used_pw:
        sink.append(Finding(
            system=system, asset_type=AssetType.CERT, language="pkcs12",
            file_path=rel, line=0, algorithm="WEAK-KEY-PASSWORD",
            category="key-protection", variant_raw=used_pw.decode(errors="replace"),
            rule_id="key-protection", confidence=Confidence.HIGH,
            severity=Severity.CRITICAL, weak=True, pq_status="broken-classical",
            pq_note="PKCS#12 使用弱/默认口令，需更换为强口令或迁移到 KMS/HSM",
            key_usage="keystore-protection"))
    key, cert, addl = loaded
    if cert is not None:
        _scan_x509(system, rel, cert.public_bytes(serialization.Encoding.PEM), sink)
    if key is not None:
        base, bits = _key_algorithm(key.public_key())
        res = _classify_key(base, bits)
        if res:
            f = _f(system, rel, f"PKCS#12 私钥 {base} {bits or ''}bit", res,
                   "private-key", {"bits": bits})
            f.language = "pkcs12"
            sink.append(f)


def scan_certificates(root: Path, system: str) -> list[Finding]:
    sink: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            ext = p.suffix.lower()
            rel = str(p.relative_to(root))
            try:
                data = p.read_bytes()
                if len(data) > 5 * 1024 * 1024:
                    continue
            except OSError:
                continue

            if ext in PKCS12_EXT:
                _scan_pkcs12(system, rel, data, sink)
                continue
            if ext in PUB_EXT:
                _scan_ssh_public(system, rel, data, sink)
                continue
            if ext not in CERT_EXT and ext not in KEY_EXT:
                continue

            markers = PEM_MARKER_RE.findall(data)
            if not markers:
                if ext in CERT_EXT:  # 可能是 DER 证书
                    _scan_x509(system, rel, data, sink)
                continue
            for marker_b in markers:
                marker = marker_b.decode()
                if "CERTIFICATE" in marker and "TRUSTED" not in marker:
                    _scan_x509(system, rel, data, sink)
                elif "PRIVATE KEY" in marker:
                    _scan_private_key(system, rel, data, marker, sink)
    # 去重
    uniq: dict[tuple, Finding] = {}
    for f in sink:
        uniq.setdefault((f.file_path, f.algorithm, f.key_usage), f)
    return list(uniq.values())
