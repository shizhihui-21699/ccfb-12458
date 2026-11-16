#!/usr/bin/env python3
"""生成样本证书与密钥（离线，仅用于演示扫描）。

覆盖：RSA1024/2048/4096、EC P-256/P-384、Ed25519、SHA1/MD5 签名证书、过期证书、
长有效期证书、加密 PEM 私钥（含弱口令）、OpenSSH 公私钥、PKCS#12。
"""
from __future__ import annotations

import datetime
import os
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

# cryptography 50 已移除 SHA1/MD5 证书签名能力，这里手工组装弱签名证书，
# 与真实世界里历史遗留证书的字节结构一致（扫描器只解析不验签）。
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import utils as x509_utils
import struct as _struct

def _legacy_sign_cert(builder: x509.CertificateBuilder, issuer_key,
                      sig_oid: str, hash_alg) -> x509.Certificate:
    """用 PKCS#1 v1.5 手工生成 MD5/SHA1 签名证书（仅用于测试样本）。

    思路：先用 SHA256 正常签发拿到结构完整的 tbsCertificate DER，
    把其中内外两处 signatureAlgorithm 的 OID 替换为弱 OID，再对新 TBS 做弱哈希签名。
    """
    tmp = builder.sign(issuer_key, hashes.SHA256())
    tbs_der = tmp.tbs_certificate_bytes
    # TBS 结构: [0]version, INTEGER serial, AlgorithmIdentifier signature, Name issuer...
    outer_hdr = _der_header_len(tbs_der)[0]
    pos = outer_hdr  # 外层 SEQUENCE 头部结束处（指向内容）
    if tbs_der[pos] == 0xA0:           # [0] EXPLICIT version
        pos += _tlv_span(tbs_der, pos)
    pos += _tlv_span(tbs_der, pos)     # serial INTEGER
    alg_start = pos
    alg_total = _tlv_span(tbs_der, pos)  # AlgorithmIdentifier SEQUENCE
    alg_block_old = tbs_der[alg_start:alg_start + alg_total]
    sha256_rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    weak_oid_enc = b"\x06" + _der_len(len(_encode_oid(sig_oid))) + _encode_oid(sig_oid)
    new_alg_block = alg_block_old.replace(sha256_rsa_oid, weak_oid_enc, 1)
    # 在 TBS 内容区（不含外层头）内替换，再重新封 SEQUENCE
    tbs_content = (tbs_der[outer_hdr:alg_start] + new_alg_block +
                   tbs_der[alg_start + alg_total:])
    tbs = b"\x30" + _der_len(len(tbs_content)) + tbs_content
    digest = hashes.Hash(hash_alg)
    digest.update(bytes(tbs))
    sig = issuer_key.sign(digest.finalize(), padding.PKCS1v15(),
                          asym_utils.Prehashed(hash_alg))
    alg_block = _sig_algorithm_block(sig_oid)
    sig_block = b"\x03" + _der_len(1 + len(sig)) + b"\x00" + sig
    body = bytes(tbs) + alg_block + sig_block
    der = b"\x30" + _der_len(len(body)) + body
    return x509.load_der_x509_certificate(der)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der_header_len(der: bytes) -> tuple[int, int]:
    """返回 (头部长度, 整个 TLV 长度)，支持短/长形式长度。"""
    b1 = der[1]
    if b1 < 0x80:
        return 2, 2 + b1
    nbytes = b1 & 0x7F
    total = 2 + nbytes + int.from_bytes(der[2:2 + nbytes], "big")
    return 2 + nbytes, total


def _tlv_span(der: bytes, pos: int) -> int:
    """返回 der[pos:] 处一个完整 TLV 的字节数。"""
    return _der_header_len(der[pos:])[1]


def _encode_oid(oid: str) -> bytes:
    arcs = [int(x) for x in oid.split(".")]
    first = arcs[0] * 40 + arcs[1]
    body = [first]
    for a in arcs[2:]:
        if a < 0x80:
            body.append(a)
        else:
            chunks = [a & 0x7F]
            a >>= 7
            while a:
                chunks.append(0x80 | (a & 0x7F))
                a >>= 7
            body.extend(reversed(chunks))
    return bytes(body)


def _sig_algorithm_block(oid: str) -> bytes:
    oid_bytes = b"\x06" + _der_len(len(_encode_oid(oid))) + _encode_oid(oid)
    null = b"\x05\x00"
    return b"\x30" + _der_len(len(oid_bytes) + len(null)) + oid_bytes + null

ROOT = pathlib.Path(__file__).resolve().parents[1] / "samples"


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _cert(subject_key, cn: str, issuer_name, issuer_key, hash_alg,
          not_before, not_after, ca=False) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("www." + cn)]),
                       critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
    try:
        return builder.sign(issuer_key, hash_alg)
    except TypeError:
        # Ed25519 不接受 hash 参数
        return builder.sign(issuer_key, None)


def _write(path: pathlib.Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mode:
        os.chmod(path, mode)


def gen_pki(out: pathlib.Path) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    past = now - datetime.timedelta(days=400)
    expired_after = now - datetime.timedelta(days=1)
    long_after = now + datetime.timedelta(days=365 * 4)

    # ---- legacy-payment-gateway: 一堆历史包袱 ----
    g = out / "legacy-payment-gateway" / "certs"
    rsa1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sha1_oid = "1.2.840.113549.1.1.5"
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("pay-legacy.example.com"))
        .issuer_name(_name("Legacy Root CA"))
        .public_key(rsa1024.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=100))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("pay-legacy.example.com"),
             x509.DNSName("www.pay-legacy.example.com")]), critical=False)
    )
    sha1_cert = _legacy_sign_cert(builder, rsa2048, sha1_oid, hashes.SHA1())
    _write(g / "pay-legacy-sha1.crt",
           sha1_cert.public_bytes(serialization.Encoding.PEM))
    _write(g / "pay-legacy-rsa1024.key",
           rsa1024.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption()), 0o600)
    # 过期的 RSA2048 证书
    expired = _cert(rsa2048, "expired-pay.example.com", _name("Legacy Root CA"),
                    rsa2048, hashes.SHA256(), past, expired_after)
    _write(g / "expired-pay.crt", expired.public_bytes(serialization.Encoding.PEM))
    # 弱口令加密的私钥（传统 PEM 封装，DES-EDE3-CBC）
    _write(g / "encrypted-weakpass.key",
           rsa2048.private_bytes(
               serialization.Encoding.PEM,
               serialization.PrivateFormat.TraditionalOpenSSL,
               serialization.BestAvailableEncryption(b"password")), 0o600)
    # PKCS#12，默认弱口令 changeit
    p12 = pkcs12.serialize_key_and_certificates(
        b"pay-gateway", rsa1024, sha1_cert, None,
        serialization.BestAvailableEncryption(b"changeit"))
    _write(g / "gateway-keystore.p12", p12, 0o600)
    # OpenSSH RSA 公钥（位长从公钥对象解析）
    _write(g / "deploy_rsa.pub",
           rsa2048.public_key().public_bytes(
               serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))

    # ---- internal-portal: 中等卫生 ----
    g = out / "internal-portal" / "ssl"
    ec256 = ec.generate_private_key(ec.SECP256R1())
    portal_cert = _cert(ec256, "portal.internal.example.com", _name("Internal CA"),
                        ec.generate_private_key(ec.SECP384R1()), hashes.SHA256(),
                        now - datetime.timedelta(days=30), now + datetime.timedelta(days=200))
    _write(g / "portal.crt", portal_cert.public_bytes(serialization.Encoding.PEM))
    _write(g / "portal-ec.key",
           ec256.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()), 0o600)
    rsa4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    long_cert = _cert(rsa4096, "vpn.internal.example.com", _name("Internal CA"),
                      rsa4096, hashes.SHA384(), now - datetime.timedelta(days=10), long_after)
    _write(g / "vpn-longlived.crt", long_cert.public_bytes(serialization.Encoding.PEM))
    # OpenSSH ed25519 私钥 + 公钥
    ed = ed25519.Ed25519PrivateKey.generate()
    _write(g / "ssh_host_ed25519_key",
           ed.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.OpenSSH,
                            serialization.NoEncryption()), 0o600)
    _write(g / "ssh_host_ed25519_key.pub",
           ed.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH))

    # ---- iot-firmware: 重灾区 ----
    g = out / "iot-firmware" / "keys"
    rsa512_like = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # 平台允许的最小
    md5_oid = "1.2.840.113549.1.1.4"
    md5_builder = (
        x509.CertificateBuilder()
        .subject_name(_name("device-0001.iot.example.com"))
        .issuer_name(_name("Device CA"))
        .public_key(rsa512_like.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past)
        .not_valid_after(expired_after)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("device-0001.iot.example.com")]), critical=False)
    )
    md5_cert = _legacy_sign_cert(md5_builder, rsa512_like, md5_oid, hashes.MD5())
    _write(g / "device-cert.pem", md5_cert.public_bytes(serialization.Encoding.PEM))
    _write(k := g / "device-rsa1024.key",
           rsa512_like.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()), 0o600)
    # 一个损坏/截断的 PEM，验证扫描器容错
    _write(g / "corrupt.pem", b"-----BEGIN CERTIFICATE-----\nTRUNCATED\n")

    # ---- data-pipeline: 现代化，含 PQ 试点材料 ----
    g = out / "data-pipeline" / "pki"
    ec384 = ec.generate_private_key(ec.SECP384R1())
    modern = _cert(ec384, "pipeline.example.com", _name("Pipeline CA"),
                   ec.generate_private_key(ec.SECP384R1()), hashes.SHA384(),
                   now - datetime.timedelta(days=5), now + datetime.timedelta(days=180))
    _write(g / "pipeline.crt", modern.public_bytes(serialization.Encoding.PEM))
    _write(g / "pipeline-ec384.key",
           ec384.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.BestAvailableEncryption(b"strong-passphrase-9f3k")),
           0o600)
    rsa3072 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_cert = _cert(rsa3072, "pq-pilot-ca.example.com", _name("PQ Pilot Root"),
                    rsa3072, hashes.SHA384(), now - datetime.timedelta(days=2),
                    now + datetime.timedelta(days=300), ca=True)
    _write(g / "pq-pilot-ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
    # ML-KEM 试点公钥占位（base64 文本，模拟 PQ 公钥分发物）
    _write(g / "mlkem768-pilot.pub",
           b"-----BEGIN ML-KEM-768 PUBLIC KEY-----\n"
           b"UExVIFBJTE9UIEtFWSBHT0VTIEhFUkUgLSBzY2FubmVyIHJlY29nbml6ZXMgYWxnb3JpdGhtIG5hbWU=\n"
           b"-----END ML-KEM-768 PUBLIC KEY-----\n")
    print("PKI 样本已生成到", out)


if __name__ == "__main__":
    gen_pki(ROOT)
