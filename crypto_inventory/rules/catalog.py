"""算法知识库：规范化命名、弱用法判定、后量子 (PQ) 状态分类。

PQ 状态四档（对齐 NIST PQC 迁移指南口径）：
- broken-classical : 经典意义上已被攻破/弃用（MD5、SHA1、ECB、DES、RSA1024…）
- pq-vulnerable    : 经典安全但 Shor 算法可破的非对称（RSA/ECDSA/Ed25519/X25519/DH…）
- pq-adjust        : Grover / 量子生日攻击下安全等级减半，需调参数（AES-128、SHA-256 抗碰撞）
- pq-safe          : 量子安全裕度充足（AES-256、SHA-384+、ML-KEM/ML-DSA 等 PQC）
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AlgInfo:
    category: str
    severity: str        # critical / high / medium / info
    weak: bool           # 经典弱用法标记
    pq_status: str
    pq_note: str


_PQ_SAFE_NOTE = "量子安全裕度充足，可作为迁移目标保留"
_ADJUST_NOTE = "量子攻击下安全强度减半，建议升级到 256 位密钥 / SHA-384 以上"
_SHOR_NOTE = "Shor 算法可在量子计算机上多项式时间破解，需迁移到 ML-KEM/ML-DSA 等后量子算法"
_BROKEN_NOTE = "经典意义上已不安全，应立即替换"

# 固定名称算法表
_CATALOG: dict[str, AlgInfo] = {
    # ---------------- 哈希 ----------------
    "MD2": AlgInfo("hash", "critical", True, "broken-classical", _BROKEN_NOTE + "（MD2 碰撞攻击）"),
    "MD4": AlgInfo("hash", "critical", True, "broken-classical", _BROKEN_NOTE + "（MD4 碰撞攻击）"),
    "MD5": AlgInfo("hash", "critical", True, "broken-classical", _BROKEN_NOTE + "（MD5 碰撞攻击，禁止用于签名/完整性）"),
    "SHA-1": AlgInfo("hash", "critical", True, "broken-classical", _BROKEN_NOTE + "（SHAttered 实际碰撞，2017 年起弃用）"),
    "RIPEMD160": AlgInfo("hash", "medium", True, "pq-adjust", "160 位摘要强度不足，建议替换为 SHA-2/SHA-3 系列"),
    "SHA-224": AlgInfo("hash", "medium", True, "pq-adjust", _ADJUST_NOTE),
    "SHA-256": AlgInfo("hash", "medium", False, "pq-adjust", _ADJUST_NOTE + "（抗碰撞场景需 SHA-384+；原像场景仍可接受）"),
    "SHA-384": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "SHA-512": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "SHA-512/256": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "SHA3-224": AlgInfo("hash", "medium", False, "pq-adjust", _ADJUST_NOTE),
    "SHA3-256": AlgInfo("hash", "medium", False, "pq-adjust", _ADJUST_NOTE),
    "SHA3-384": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "SHA3-512": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "BLAKE2B": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "BLAKE2S": AlgInfo("hash", "medium", False, "pq-adjust", _ADJUST_NOTE),
    "BLAKE3": AlgInfo("hash", "info", False, "pq-safe", _PQ_SAFE_NOTE),

    # ---------------- 对称加密 ----------------
    "DES": AlgInfo("symmetric", "critical", True, "broken-classical", _BROKEN_NOTE + "（56 位密钥，暴力可破）"),
    "DES-EDE3": AlgInfo("symmetric", "critical", True, "broken-classical", "3DES 已被 NIST 2023 年退役（Sweet32 生日攻击）"),
    "3DES": AlgInfo("symmetric", "critical", True, "broken-classical", "3DES 已被 NIST 2023 年退役（Sweet32 生日攻击）"),
    "RC4": AlgInfo("hash", "critical", True, "broken-classical", _BROKEN_NOTE + "（RC4 流密码偏差攻击，TLS/SSH 均已禁用）"),
    "BLOWFISH": AlgInfo("symmetric", "medium", True, "pq-adjust", "64 位块大小存在 Sweet32 类风险，建议 AES 替代"),
    "CHACHA20-POLY1305": AlgInfo("symmetric", "info", False, "pq-safe", _PQ_SAFE_NOTE + "（256 位密钥 + AEAD）"),
    "CHACHA20": AlgInfo("symmetric", "info", False, "pq-safe", _PQ_SAFE_NOTE + "（注意需配合认证加密）"),

    # ---------------- 非对称 ----------------
    "RSA": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（RSA 密钥交换/签名）"),
    "DSA": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（DSA 签名）"),
    "DH": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（有限域 Diffie-Hellman）"),
    "ECDH": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（椭圆曲线 DH 密钥协商）"),
    "ECDSA": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（椭圆曲线签名）"),
    "ED25519": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（EdDSA 签名，经典安全但非后量子）"),
    "ED448": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE),
    "X25519": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE + "（ECDH 曲线点）"),
    "X448": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE),
    "ECIES": AlgInfo("asymmetric", "high", False, "pq-vulnerable", _SHOR_NOTE),
    # NIST FIPS 203/204/205 后量子算法
    "ML-KEM-512": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 203 后量子密钥封装（最低参数集，建议 768+）"),
    "ML-KEM-768": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 203 后量子密钥封装，NIST 推荐迁移目标"),
    "ML-KEM-1024": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 203 后量子密钥封装（最高参数集）"),
    "ML-DSA-44": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 204 后量子签名（最低参数集，建议 65+）"),
    "ML-DSA-65": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 204 后量子签名，NIST 推荐迁移目标"),
    "ML-DSA-87": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 204 后量子签名（最高参数集）"),
    "FALCON-512": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 204 备选后量子签名（FN-DSA）"),
    "FALCON-1024": AlgInfo("asymmetric", "info", False, "pq-safe", "FIPS 204 备选后量子签名（FN-DSA）"),
    "HQC-128": AlgInfo("asymmetric", "info", False, "pq-safe", "NIST 第四轮备选后量子 KEM"),

    # ---------------- KDF / 口令哈希 ----------------
    "PBKDF2": AlgInfo("kdf", "info", False, "pq-adjust", "本身非 PQ 风险点；注意迭代次数与底层哈希，优先 Argon2/id"),
    "HKDF": AlgInfo("kdf", "info", False, "pq-safe", _PQ_SAFE_NOTE + "（需配合 PQ 密钥交换）"),
    "SCRYPT": AlgInfo("kdf", "info", False, "pq-safe", _PQ_SAFE_NOTE),
    "ARGON2": AlgInfo("kdf", "info", False, "pq-safe", "口令哈希首选，" + _PQ_SAFE_NOTE),
    "BCRYPT": AlgInfo("kdf", "info", False, "pq-adjust", "经典可用；新系统建议 Argon2id"),

    # ---------------- 随机数 ----------------
    "INSECURE-RNG": AlgInfo("rng", "critical", True, "broken-classical", "非密码学随机数用于安全场景，必须替换为 CSPRNG"),
    "CSPRNG": AlgInfo("rng", "info", False, "pq-safe", _PQ_SAFE_NOTE + "（os.urandom / secrets / SecureRandom）"),

    # ---------------- 模式 / 协议级弱用法 ----------------
    "ECB-MODE": AlgInfo("symmetric", "critical", True, "broken-classical",
                        _BROKEN_NOTE + "（ECB 模式：相同明文块产生相同密文块，泄露数据模式）"),
    "JWT-NONE": AlgInfo("signature", "critical", True, "broken-classical",
                        _BROKEN_NOTE + "（JWT alg=none 禁用签名，令牌可被任意伪造）"),

    # ---------------- TLS 协议版本 ----------------    "SSLV2": AlgInfo("tls-protocol", "critical", True, "broken-classical", _BROKEN_NOTE + "（SSL 2.0）"),
    "SSLV3": AlgInfo("tls-protocol", "critical", True, "broken-classical", _BROKEN_NOTE + "（POODLE 攻击）"),
    "TLS1.0": AlgInfo("tls-protocol", "critical", True, "broken-classical", "RFC 8996 已弃用（BEAST/降级攻击）"),
    "TLS1.1": AlgInfo("tls-protocol", "critical", True, "broken-classical", "RFC 8996 已弃用"),
    "TLS1.2": AlgInfo("tls-protocol", "high", False, "pq-vulnerable", "协议本身可用，但其经典密钥交换/签名算法受 Shor 影响，需混合 PQ 套件"),
    "TLS1.3": AlgInfo("tls-protocol", "info", False, "pq-adjust", "现代协议；启用 X25519MLKEM768 等混合组后即达成 PQ 防护"),
}

# 别名 → 规范名
_ALIASES: dict[str, str] = {
    "MD5SUM": "MD5", "MD-5": "MD5",
    "SHA1": "SHA-1", "SHA-160": "SHA-1", "SHA1HEX": "SHA-1",
    "SHA256": "SHA-256", "SHA2-256": "SHA-256",
    "SHA384": "SHA-384", "SHA2-384": "SHA-384",
    "SHA512": "SHA-512", "SHA2-512": "SHA-512",
    "SHA3-256": "SHA3-256", "KECCAK-256": "SHA3-256",
    "TRIPLEDES": "3DES", "TRIPLE-DES": "3DES", "DESEDE": "3DES", "DES-EDE": "3DES",
    "ARCFOUR": "RC4", "ARC4": "RC4",
    "AESGCM": "AES", "RSAES": "RSA", "RSASSA-PKCS1-V1_5": "RSA", "RSA-PSS": "RSA",
    "EDDSA": "ED25519",
    "CURVE25519": "X25519",
    "PBKDF2-HMAC-SHA1": "PBKDF2", "PBKDF2-HMAC-SHA256": "PBKDF2", "PBKDF2WITHHMACSHA256": "PBKDF2",
    "PBKDF2WITHHMACSHA1": "PBKDF2",
    "RANDOM": "INSECURE-RNG", "MATH.RANDOM": "INSECURE-RNG", "JAVA.UTIL.RANDOM": "INSECURE-RNG",
    "SECURERANDOM": "CSPRNG", "OS.URANDOM": "CSPRNG", "SECRETS": "CSPRNG", "SYSTEMRANDOM": "CSPRNG",
    "SSL2": "SSLV2", "SSL3": "SSLV3", "SSLV23": "SSLV3",
    "TLSV1": "TLS1.0", "TLSV1.0": "TLS1.0", "TLSV1.1": "TLS1.1",
    "TLSV1.2": "TLS1.2", "TLSV1.3": "TLS1.3",
    "ML-KEM": "ML-KEM-768", "KYBER": "ML-KEM-768", "CRYSTALS-KYBER": "ML-KEM-768",
    "ML-DSA": "ML-DSA-65", "DILITHIUM": "ML-DSA-65", "CRYSTALS-DILITHIUM": "ML-DSA-65",
    "FN-DSA": "FALCON-1024",
}

_AES_RE = re.compile(r"^AES[_\-]?(\d{3})[_\-]?(ECB|CBC|CFB|OFB|CTR|GCM|CCM|OCB|XTS|SIC)(?:[_\-]?(\d+))?$", re.I)
_RSA_RE = re.compile(r"^RSA[_\-]?(\d{3,5})$")
_DSA_RE = re.compile(r"^DSA[_\-]?(\d{3,5})$")
_DH_RE = re.compile(r"^(?:DH|DIFFIEHELLMAN)[_\-]?(\d{3,5})$")
_EC_RE = re.compile(r"^(ECDSA|ECDH|ECIES)[_\-]?(P-?\d+|SECP\d+K?R?\d|ED25519|X25519|SECP256K1|BRAINPOOL\w+)?$", re.I)
_SSH_KEX_RE = re.compile(r"^(DIFFIE-HELLMAN-GROUP|ECDH-SHA2|CURVE25519|X25519|MLKEM|SNTRUP)([\w\-]*)$", re.I)


def _normalize_token(name: str) -> str:
    upper = name.strip().upper()
    # TLS/SSL 版本要在标点替换之前识别（TLSv1.2 的点不能先变成横杠）
    m = re.match(r"^TLSV?(\d)(?:[.\-](\d))?$", upper)
    if m:
        return f"TLS{m.group(1)}.{m.group(2) or '0'}"
    m = re.match(r"^SSLV?(\d)$", upper)
    if m:
        return f"SSLV{m.group(1)}"
    return re.sub(r"[\s./]+", "-", upper).strip("-")


def classify(raw_name: str, *, key_bits: int | None = None,
             signature_hash: str | None = None) -> tuple[str, AlgInfo] | None:
    """把任意写法的算法名归一化并返回 (规范名, AlgInfo)。无法识别返回 None。

    key_bits: RSA/DSA/DH 位长（证书/密钥场景）
    signature_hash: 证书签名哈希，用于把签名算法拆成 非对称+哈希 两个判断
    """
    if not raw_name:
        return None
    token = _normalize_token(raw_name)
    token = token.replace("_", "-")

    # 1. 精确表 / 别名
    canonical = _ALIASES.get(token, token)
    if canonical in _CATALOG:
        return canonical, _CATALOG[canonical]

    # 2. AES 带模式与密钥长度
    m = _AES_RE.match(token)
    if m:
        bits, mode = int(m.group(1)), m.group(2).upper()
        name = f"AES-{bits}-{mode}"
        if mode == "ECB":
            return name, AlgInfo("symmetric", "critical", True, "broken-classical",
                                 _BROKEN_NOTE + "（ECB 模式保留明文模式，确定性加密泄露数据模式）")
        if mode == "CBC":
            pq = "pq-adjust" if bits < 256 else "pq-safe"
            return name, AlgInfo("symmetric", "medium", True, pq,
                                 "CBC 非认证加密，存在填充 oracle 风险，建议 GCM/CCM；" + _ADJUST_NOTE if bits < 256
                                 else "CBC 非认证加密，存在填充 oracle 风险，建议 GCM/CCM")
        if bits == 128:
            return name, AlgInfo("symmetric", "medium", False, "pq-adjust", _ADJUST_NOTE)
        if bits == 192:
            return name, AlgInfo("symmetric", "info", False, "pq-safe", "192 位密钥量子后约 96 位强度，可接受；优先 256 位")
        return name, AlgInfo("symmetric", "info", False, "pq-safe", _PQ_SAFE_NOTE)
    if token in ("AES", "AES128", "AES192", "AES256"):
        bits = int(token[3:]) if len(token) > 3 else 128
        return classify(f"AES-{bits}-CBC")  # 未指定模式按最常见保守处理

    # 2b. OpenSSL 风格 DES/3DES/RC4 密码名（des-ede3-cbc / des-ecb / rc4-40 ...）
    if re.match(r"^DES-EDE3(?:-(?:CBC|ECB|CFB|OFB))?$", token):
        return "3DES", _CATALOG["3DES"]
    if re.match(r"^DES(?:-(?:CBC|ECB|CFB|OFB))?$", token):
        return "DES", _CATALOG["DES"]
    if re.match(r"^RC4(?:-\d+)?$", token):
        return "RC4", _CATALOG["RC4"]

    # 2c. OpenSSL EVP 函数名（aes_128_ecb / des_ede3_ecb / chacha20_poly1305 ...）
    m = re.match(r"^AES_(\d{3})_(ECB|CBC|GCM|CCM|CTR|OFB|CFB|XTS)$", token)
    if m:
        return classify(f"AES-{m.group(1)}-{m.group(2)}")
    if re.match(r"^DES_EDE3(?:_(?:CBC|ECB|CFB|OFB))?$", token):
        return "3DES", _CATALOG["3DES"]
    if token.startswith("CHACHA20"):
        return ("CHACHA20-POLY1305", _CATALOG["CHACHA20-POLY1305"]) if "POLY1305" in token \
            else ("CHACHA20", _CATALOG["CHACHA20"])

    # 3. RSA / DSA / DH 带位长
    for rx, base, cat in ((_RSA_RE, "RSA", "asymmetric"), (_DSA_RE, "DSA", "asymmetric"),
                          (_DH_RE, "DH", "asymmetric")):
        m = rx.match(token)
        if m:
            bits = int(m.group(1))
            name = f"{base}-{bits}"
            if bits < 2048:
                return name, AlgInfo(cat, "critical", True, "broken-classical",
                                     _BROKEN_NOTE + f"（{base} {bits} 位可被因式分解/攻击，最低要求 2048）")
            if bits < 3072:
                return name, AlgInfo(cat, "high", False, "pq-vulnerable",
                                     _SHOR_NOTE + f"（{bits} 位经典强度可接受，2030 后建议 3072）")
            return name, AlgInfo(cat, "high", False, "pq-vulnerable",
                                 _SHOR_NOTE + f"（{bits} 位经典强度充足）")
    if key_bits and token in ("RSA", "DSA", "DH"):
        return classify(f"{token}-{key_bits}")

    # 4. 椭圆曲线带曲线名
    m = _EC_RE.match(token)
    if m:
        base = m.group(1).upper()
        curve = (m.group(2) or "").upper().replace("SECP", "P-").replace("P-", "P", 1)
        name = f"{base}-{curve}" if curve else base
        if curve in ("P192", "P224", "SECP192K1"):
            return name, AlgInfo("asymmetric", "critical", True, "broken-classical",
                                 _BROKEN_NOTE + f"（{curve} 曲线强度不足）")
        info = _CATALOG.get(base)
        return name, info

    # 5. SSH 命名的 KEX / hostkey（如 diffie-hellman-group14-sha256）
    m = _SSH_KEX_RE.match(token)
    if m:
        rest = m.group(2)
        if "GROUP1-" in rest or "GROUP-EXCHANGE-SHA1" in rest or rest.endswith("-SHA1"):
            return token.title(), AlgInfo("kex", "critical", True, "broken-classical",
                                          "SSH 弱密钥交换（SHA1/1024 位群），需禁用")
        if "MLKEM" in token or "SNTRUP" in token:
            return token, AlgInfo("kex", "info", False, "pq-safe", "后量子/混合密钥交换，迁移目标")
        return token, AlgInfo("kex", "high", False, "pq-vulnerable",
                              _SHOR_NOTE + "（SSH 经典 KEX，需迁移到 mlkem768x25519 等混合组）")

    # 6. HMAC / SSH MAC
    if token.startswith("HMAC-") or token.startswith("HMAC"):
        inner = token.replace("HMAC-", "").replace("HMAC", "") or "SHA-256"
        if inner in ("MD5", "SHA1", "SHA-1"):
            return token, AlgInfo("mac", "critical", True, "broken-classical",
                                  _BROKEN_NOTE + "（基于弱哈希的 MAC）")
        canon_inner, _ = classify(inner) or (inner, None)
        if canon_inner and canon_inner in ("SHA-256", "SHA-224", "SHA3-256"):
            return f"HMAC-{canon_inner}", AlgInfo("mac", "info", False, "pq-adjust",
                                                  "HMAC 抗量子降级弱于裸哈希；256 位可接受，高安全域选 SHA-384")
        if canon_inner:
            return f"HMAC-{canon_inner}", AlgInfo("mac", "info", False, "pq-safe", _PQ_SAFE_NOTE)

    return None


def split_java_cipher(transformation: str) -> list[tuple[str, int]]:
    """解析 Java/Node/OpenSSL 风格的 cipher transformation 字符串。

    例: 'AES/CBC/PKCS5Padding' -> [('AES-128-CBC', line)], 'DESede/ECB/...' -> 3DES+ECB
    返回 [(canonical_algorithm, hint_line_offset)]；ECB 等模式问题单独产出。
    """
    parts = re.split(r"[/\s]+", transformation.strip())
    if not parts:
        return []
    algo = parts[0].upper()
    mode = parts[1].upper() if len(parts) > 1 else ""
    out: list[str] = []
    if algo in ("DESEDE", "DES-EDE3", "TRIPLEDES"):
        out.append("3DES")
        if mode == "ECB":
            out.append("AES-128-ECB".replace("AES-128-ECB", "__ECB_MODE__"))  # 标记，见调用方
    elif algo == "DES":
        out.append("DES")
    elif algo == "RC4" or algo.startswith("ARCFOUR"):
        out.append("RC4")
    elif algo == "RSA":
        out.append("RSA")
    elif algo.startswith("AES"):
        m = re.match(r"AES(\d+)", algo)
        bits = int(m.group(1)) if m else 128
        out.append(f"AES-{bits}-{mode or 'CBC'}")
    elif algo in ("CHACHA20", "CHACHA20-POLY1305"):
        out.append("CHACHA20-POLY1305" if "POLY1305" in transformation.upper() else "CHACHA20")
    return [(x, 0) for x in out]
