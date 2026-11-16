"""算法知识库归一化与分级测试。"""
from __future__ import annotations

import pytest

from crypto_inventory.rules.catalog import classify, split_java_cipher


@pytest.mark.parametrize("raw,canonical,pq", [
    ("md5", "MD5", "broken-classical"),
    ("MD5", "MD5", "broken-classical"),
    ("SHA1", "SHA-1", "broken-classical"),
    ("sha-1", "SHA-1", "broken-classical"),
    ("SHA256", "SHA-256", "pq-adjust"),
    ("sha384", "SHA-384", "pq-safe"),
    ("AES-128-ECB", "AES-128-ECB", "broken-classical"),
    ("aes-256-gcm", "AES-256-GCM", "pq-safe"),
    ("AES256/GCM", "AES-256-GCM", "pq-safe"),
    ("RSA-1024", "RSA-1024", "broken-classical"),
    ("RSA-2048", "RSA-2048", "pq-vulnerable"),
    ("RSA-4096", "RSA-4096", "pq-vulnerable"),
    ("ED25519", "ED25519", "pq-vulnerable"),
    ("X25519", "X25519", "pq-vulnerable"),
    ("ML-KEM-768", "ML-KEM-768", "pq-safe"),
    ("KYBER", "ML-KEM-768", "pq-safe"),
    ("ML-DSA-65", "ML-DSA-65", "pq-safe"),
    ("3DES", "3DES", "broken-classical"),
    ("RC4", "RC4", "broken-classical"),
    ("chacha20-poly1305", "CHACHA20-POLY1305", "pq-safe"),
    ("INSECURE-RNG", "INSECURE-RNG", "broken-classical"),
    ("TLSv1", "TLS1.0", "broken-classical"),
    ("TLSv1.3", "TLS1.3", "pq-adjust"),
])
def test_normalize_and_pq_status(raw, canonical, pq):
    res = classify(raw)
    assert res is not None, raw
    name, info = res
    assert name == canonical
    assert info.pq_status == pq


def test_unknown_returns_none():
    assert classify("not-an-algorithm") is None
    assert classify("") is None


def test_java_transformation_split():
    parts = split_java_cipher("DESede/ECB/PKCS5Padding")
    names = [p[0] for p in parts]
    assert "3DES" in names
    assert "__ECB_MODE__" in names

    parts = split_java_cipher("AES/CBC/PKCS5Padding")
    assert parts[0][0] == "AES-128-CBC"


def test_rsa_key_size_thresholds():
    assert classify("RSA-1024")[1].severity == "critical"
    assert classify("RSA-2048")[1].severity == "high"
    assert classify("RSA-2048")[1].pq_status == "pq-vulnerable"


def test_aes_modes():
    assert classify("AES-128-ECB")[1].weak is True
    assert classify("AES-256-GCM")[1].weak is False
    assert classify("AES-128-CBC")[1].weak is True
