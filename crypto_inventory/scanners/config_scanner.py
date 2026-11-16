"""配置文件扫描器：TLS 密码套件 / 协议版本 / SSH 套件。

支持文件：nginx.conf / apache httpd / haproxy.cfg / 应用 yaml,yml,properties,json,toml,ini,conf /
ssh 相关配置与 sshd_config。输出 Finding 的 asset_type=config，language=config。
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..models import AssetType, Confidence, Finding, Severity
from ..rules.catalog import AlgInfo, classify, _CATALOG  # type: ignore

CONFIG_EXT = {".conf", ".cfg", ".ini", ".yaml", ".yml", ".properties",
              ".json", ".toml", ".env", ".txt"}
CONFIG_NAME_HINTS = ("nginx", "apache", "httpd", "haproxy", "ssl", "tls",
                     "sshd", "ssh", "application", "config", "settings", "env")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist",
             "build", "target", "vendor"}

# ----------------------------------------------------------- TLS 套件解码

# IANA/OpenSSL 名称片段 → (规范算法名, 组件类别)
_KEX_MAP = {
    "RSA": ("RSA", "kex"), "DHE": ("DH", "kex"), "DH": ("DH", "kex"),
    "ECDHE": ("ECDH", "kex"), "ECDH": ("ECDH", "kex"),
    "TLS13": (None, "kex"),  # TLS1.3 套件无独立 kex（由 named group 决定）
}
_AUTH_MAP = {
    "RSA": ("RSA", "auth"), "DSS": ("DSA", "auth"), "ECDSA": ("ECDSA", "auth"),
    "ED25519": ("ED25519", "auth"),
}
_ENC_MAP = {
    "3DES": ("3DES", "symmetric"), "DES": ("DES", "symmetric"),
    "RC4": ("RC4", "symmetric"), "AES128": ("AES-128", "symmetric"),
    "AES256": ("AES-256", "symmetric"),
    "CHACHA20": ("CHACHA20-POLY1305", "symmetric"),
    "ARIA128": ("ARIA-128", "symmetric"), "ARIA256": ("ARIA-256", "symmetric"),
    "CAMELLIA128": ("CAMELLIA-128", "symmetric"),
    "CAMELLIA256": ("CAMELLIA-256", "symmetric"),
    "SEED": ("SEED", "symmetric"), "IDEA": ("IDEA", "symmetric"),
}
_MODE_MAP = {
    "ECB": "ECB", "CBC": "CBC", "GCM": "GCM", "CCM": "CCM",
    "CCM8": "CCM", "CTR": "CTR", "POLY1305": "POLY1305",
}
_HASH_MAP = {
    "MD5": "MD5", "SHA": "SHA-1", "SHA1": "SHA-1",
    "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
}
_TLS13_SUITES = {
    "TLS_AES_256_GCM_SHA384": [("AES-256-GCM", "symmetric"), ("SHA-384", "hash")],
    "TLS_CHACHA20_POLY1305_SHA256": [("CHACHA20-POLY1305", "symmetric"), ("SHA-256", "hash")],
    "TLS_AES_128_GCM_SHA256": [("AES-128-GCM", "symmetric"), ("SHA-256", "hash")],
}


def decode_tls_suite(name: str) -> list[tuple[str, str, bool]]:
    """把一个 TLS 套件名拆成组件。返回 [(canonical, category, is_weak_component)]。

    同时支持 IANA 名（TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384）与
    OpenSSL 名（ECDHE-RSA-AES256-GCM-SHA384）。
    """
    original = name.strip().upper()
    if original in _TLS13_SUITES:
        out = [(c, cat, bool((classify(c) or [None, None])[1] and classify(c)[1].weak))
               for c, cat in _TLS13_SUITES[original]]
        out.append(("TLS1.3", "tls-protocol", False))
        return out

    n = original.replace("_", "-")
    # 去掉 TLS- 前缀与 WITH / EXPORT 等连接词
    if n.startswith("TLS-"):
        n = n[4:]
    tokens = [t for t in n.split("-") if t and t not in ("WITH",)]
    # IANA 命名把 AES/ARIA/CAMELLIA 与位长、模式拆成独立 token，先合并
    # 例: [AES, 128, CBC] -> [AES128, CBC]；[3DES, EDE, CBC] 保持不变由对称段消费
    merged: list[str] = []
    k = 0
    while k < len(tokens):
        t = tokens[k]
        if t in ("AES", "ARIA", "CAMELLIA") and k + 1 < len(tokens) and tokens[k + 1].isdigit():
            merged.append(f"{t}{tokens[k + 1]}")
            k += 2
            continue
        merged.append(t)
        k += 1
    tokens = merged
    is_export = "EXPORT" in tokens
    is_null = "NULL" in tokens
    is_anon = "ANON" in tokens
    tokens = [t for t in tokens if t not in ("EXPORT", "NULL", "ANON")]
    out: list[tuple[str, str, bool]] = []
    i = 0

    # 1. 密钥交换 + 认证
    if tokens and tokens[0] in _KEX_MAP:
        canon, cat = _KEX_MAP[tokens[0]]
        if canon:
            out.append((canon, cat, False))
        i = 1
    if i < len(tokens) and tokens[i] in _AUTH_MAP:
        canon, cat = _AUTH_MAP[tokens[i]]
        out.append((canon, cat, False))
        i += 1
    # 无 KEX 前缀的 RSA 套件（AES128-SHA / RSA-WITH-AES...）：RSA 既是 kex 又是 auth
    if i == 0 and tokens and tokens[0] == "RSA":
        out.append(("RSA", "kex", False))
        i = 1

    # 2. 对称加密：可能跨多 token（3DES-EDE-CBC / AES-128-CBC / RC4-40）
    if i < len(tokens):
        consumed, sym = _decode_symmetric(tokens[i:])
        if sym:
            out.extend(sym)
            i += consumed

    # 3. 摘要（最后一个可识别 hash token）
    while i < len(tokens):
        t = tokens[i]
        if t in _HASH_MAP:
            h = _HASH_MAP[t]
            res = classify(h)
            out.append((h, "hash", bool(res and res[1].weak)))
        i += 1

    if is_anon:
        out.append(("RSA", "auth", True))   # 匿名套件无认证
    if is_export:
        out.append(("RSA-512", "asymmetric", True))
    if is_null:
        out.append(("RC4", "symmetric", True))  # NULL 加密比 RC4 更糟，借用最弱条目提示
    return out


def _decode_symmetric(tokens: list[str]) -> tuple[int, list[tuple[str, str, bool]]]:
    """消费对称段 token，返回 (消费 token 数, 组件列表)。"""
    t0 = tokens[0]
    # 3DES: 3DES-EDE-CBC / DES-CBC3 / DES-EDE3-CBC
    if t0 in ("3DES", "DESEDE", "DES-EDE3") or (t0 == "DES" and len(tokens) > 1 and tokens[1] in ("CBC3", "EDE3", "EDE")):
        return (3 if t0 == "DES" and len(tokens) > 1 and tokens[1] in ("EDE3", "EDE") else
                min(3, len(tokens)) if t0 == "DES" else min(2, len(tokens))), [("3DES", "symmetric", True)]
    if t0 == "DES":
        # DES-CBC / DES-40
        return min(2, len(tokens)), [("DES", "symmetric", True)]
    if t0 in ("RC4", "ARCFOUR"):
        # RC4-40 中的 40 是密钥位长；MD5/SHA 等哈希 token 留给第 3 段
        consume = 2 if len(tokens) > 1 and tokens[1].isdigit() else 1
        return consume, [("RC4", "symmetric", True)]
    if t0 in ("SEED", "IDEA"):
        return 1, [(t0, "symmetric", True)]
    if t0.startswith("CHACHA20"):
        return min(2, len(tokens)), [("CHACHA20-POLY1305", "symmetric", False)]
    if t0 in ("ARIA128", "ARIA256", "CAMELLIA128", "CAMELLIA256"):
        base = t0.replace("ARIA", "ARIA-").replace("CAMELLIA", "CAMELLIA-")
        mode = tokens[1] if len(tokens) > 1 and tokens[1] in _MODE_MAP else None
        canon = f"{base}-{mode}" if mode else base
        return (2 if mode else 1), [(canon, "symmetric", mode in ("ECB", "CBC"))]
    if t0 in _ENC_MAP:
        base, cat = _ENC_MAP[t0]
        mode = tokens[1] if len(tokens) > 1 and tokens[1] in _MODE_MAP else None
        if mode:
            if base.startswith("AES"):
                canon = f"{base}-{mode}"
                weak = mode in ("ECB", "CBC")
            else:
                canon, weak = base, True
            return 2, [(canon, cat, weak)]
        return 1, [(base, cat, base in ("3DES", "DES", "RC4"))]
    return 0, []


# SSH 套件：openssh 命名直接查 catalog；补充表
_SSH_EXTRA = {
    "3DES-CBC": ("3DES", "symmetric", True),
    "AES128-CBC": ("AES-128-CBC", "symmetric", True),
    "AES192-CBC": ("AES-192-CBC", "symmetric", True),
    "AES256-CBC": ("AES-256-CBC", "symmetric", True),
    "AES128-CTR": ("AES-128-CTR", "symmetric", False),
    "AES192-CTR": ("AES-192-CTR", "symmetric", False),
    "AES256-CTR": ("AES-256-CTR", "symmetric", False),
    "AES128-GCM@OPENSSSH.COM": ("AES-128-GCM", "symmetric", False),
    "AES256-GCM@OPENSSSH.COM": ("AES-256-GCM", "symmetric", False),
    "CHACHA20-POLY1305@OPENSSSH.COM": ("CHACHA20-POLY1305", "symmetric", False),
    "ARCFOUR": ("RC4", "symmetric", True),
    "ARCFOUR128": ("RC4", "symmetric", True),
    "BLOWFISH-CBC": ("BLOWFISH", "symmetric", True),
    "CAST128-CBC": ("BLOWFISH", "symmetric", True),
    "HMAC-MD5": ("HMAC-MD5", "mac", True),
    "HMAC-MD5-96": ("HMAC-MD5", "mac", True),
    "HMAC-SHA1": ("HMAC-SHA-1", "mac", True),
    "HMAC-SHA1-96": ("HMAC-SHA-1", "mac", True),
    "HMAC-SHA2-256": ("HMAC-SHA-256", "mac", False),
    "HMAC-SHA2-512": ("HMAC-SHA-512", "mac", False),
    "UMAC-64@OPENSSSH.COM": ("HMAC-SHA-1", "mac", True),
    "UMAC-128@OPENSSSH.COM": ("HMAC-SHA-256", "mac", False),
    "SSH-RSA": ("RSA-2048", "asymmetric", False),
    "RSA-SHA2-256": ("RSA-2048", "asymmetric", False),
    "RSA-SHA2-512": ("RSA-2048", "asymmetric", False),
    "ECDSA-SHA2-NISTP256": ("ECDSA-P256", "asymmetric", False),
    "ECDSA-SHA2-NISTP384": ("ECDSA-P384", "asymmetric", False),
    "ECDSA-SHA2-NISTP521": ("ECDSA-P521", "asymmetric", False),
    "SSH-ED25519": ("ED25519", "asymmetric", False),
    "SSH-DSS": ("DSA-1024", "asymmetric", True),
    "DIFFIE-HELLMAN-GROUP1-SHA1": ("DH-1024", "kex", True),
    "DIFFIE-HELLMAN-GROUP14-SHA1": ("DH-2048", "kex", True),
    "DIFFIE-HELLMAN-GROUP14-SHA256": ("DH-2048", "kex", False),
    "DIFFIE-HELLMAN-GROUP16-SHA512": ("DH-4096", "kex", False),
    "DIFFIE-HELLMAN-GROUP18-SHA512": ("DH-8192", "kex", False),
    "DIFFIE-HELLMAN-GROUP-EXCHANGE-SHA1": ("DH-2048", "kex", True),
    "DIFFIE-HELLMAN-GROUP-EXCHANGE-SHA256": ("DH-2048", "kex", False),
    "ECDH-SHA2-NISTP256": ("ECDH-P256", "kex", False),
    "ECDH-SHA2-NISTP384": ("ECDH-P384", "kex", False),
    "ECDH-SHA2-NISTP521": ("ECDH-P521", "kex", False),
    "CURVE25519-SHA256": ("X25519", "kex", False),
    "CURVE25519-SHA256@LIBSSH.ORG": ("X25519", "kex", False),
    "SNTRUP761X25519-SHA512@OPENSSSH.COM": ("SNTRUP761", "kex", False),
    "MLKEM768X25519-SHA256": ("ML-KEM-768", "kex", False),
    "MLKEM768X25519-SHA256@OPENSSSH.COM": ("ML-KEM-768", "kex", False),
    "MLKEM1024X448-SHA512@OPENSSSH.COM": ("ML-KEM-1024", "kex", False),
}


def decode_ssh_alg(name: str) -> tuple[str, str, bool] | None:
    key = name.strip().upper()
    if key in _SSH_EXTRA:
        return _SSH_EXTRA[key]
    res = classify(key)
    if res:
        canon, info = res
        return canon, info.category, info.weak
    # 小写 openssh 名在 catalog 无精确匹配时，按已知前缀做兜底映射
    low = name.strip().lower()
    if low.startswith("chacha20-poly1305"):
        return "CHACHA20-POLY1305", "symmetric", False
    if low.startswith("aes") and "gcm" in low:
        bits = "256" if "256" in low else "128"
        return f"AES-{bits}-GCM", "symmetric", False
    if low.startswith("aes") and "cbc" in low:
        bits = "256" if "256" in low else "128"
        return f"AES-{bits}-CBC", "symmetric", True
    return None


# ----------------------------------------------------------- 配置键匹配

# (key 正则, 取值类型: list/word/protocol, 来源说明)
_KEY_PATTERNS = [
    (re.compile(r"ssl_ciphers|SSLCipherSuite|cipher[-_]?suite|ciphers?\b", re.I), "tls-list"),
    (re.compile(r"ssl_protocols|SSLProtocol|tls[-_]?version|min[-_]?tls|minimum[-_]?tls|"
                r"protocol[-_]?versions?|enabled[-_]?protocols?", re.I), "tls-proto"),
    (re.compile(r"named[_\-]?groups?|elliptic[_\-]?curves?|curves?|curve[-_]?preferences", re.I), "groups"),
    (re.compile(r"(?:^|[._-])kex(?:algorithms)?$|kexalgorithms", re.I), "ssh-list"),
    (re.compile(r"hostkeyalgorithms|host[-_]?key", re.I), "ssh-list"),
    (re.compile(r"(?:^|[._-])macs?$", re.I), "ssh-list"),
    (re.compile(r"^\s*Ciphers\b", re.I), "ssh-list"),
    (re.compile(r"signature[-_]?hash|signing[-_]?algorithm|digest", re.I), "tls-list"),
]
_PROTO_RE = re.compile(r"(SSLv?2|SSLv?3|TLSv?1(?:\.\d)?)", re.I)
_LIST_SPLIT_RE = re.compile(r"[\s,;:]+")
# nginx !aNULL 这类修饰
_BANG_PREFIX = re.compile(r"^[!+\-]+")


def _config_finding(system: str, rel: str, line_no: int, raw: str,
                    canonical: str, info: AlgInfo, category: str,
                    confidence: Confidence, context: str) -> Finding:
    return Finding(
        system=system, asset_type=AssetType.CONFIG, language="config",
        file_path=rel, line=line_no, algorithm=canonical, category=category,
        variant_raw=raw[:200], rule_id="config-suite", confidence=confidence,
        severity=Severity(info.severity), weak=info.weak,
        pq_status=info.pq_status, pq_note=info.pq_note, context=context.strip()[:300],
    )


def _handle_value(system: str, rel: str, line_no: int, key: str, value: str,
                  kind: str, sink: list[Finding]) -> None:
    ctx_line = f"{key} {value}"
    if kind == "tls-proto":
        for m in _PROTO_RE.finditer(value):
            token = m.group(1).upper().replace("TLSV", "TLS").replace("SSLV", "SSL")
            # TLSv1（无点）即 TLS 1.0
            if re.fullmatch(r"TLS\d", token):
                token += ".0"
            res = classify(token)
            if res:
                sink.append(_config_finding(system, rel, line_no, m.group(1),
                                            res[0], res[1], "tls-protocol",
                                            Confidence.HIGH, ctx_line))
        return

    if kind == "groups":
        for g in _LIST_SPLIT_RE.split(value):
            g = g.strip().strip("[]\"'")
            if not g:
                continue
            up = g.upper()
            if "MLKEM" in up or "KYBER" in up or "SNTRUP" in up:
                canon = "ML-KEM-768" if "768" in up or "KYBER" in up else (
                    "ML-KEM-1024" if "1024" in up else "ML-KEM-512")
                info = _CATALOG[canon]
                sink.append(_config_finding(system, rel, line_no, g, canon, info,
                                            "kex", Confidence.HIGH, ctx_line))
            elif up in ("X25519", "SECP256R1", "SECP384R1", "SECP521R1", "PRIME256V1"):
                canon = "X25519" if up == "X25519" else "ECDH-" + up.replace("SECP", "P").replace("PRIME256V1", "P256")
                res = classify(canon) or classify("ECDH")
                if res:
                    sink.append(_config_finding(system, rel, line_no, g, res[0], res[1],
                                                "kex", Confidence.HIGH, ctx_line))
        return

    is_ssh = kind == "ssh-list"
    for item in _LIST_SPLIT_RE.split(value):
        item = _BANG_PREFIX.sub("", item.strip().strip("[]\"'"))
        if not item or item in ("on", "off", "HIGH", "MEDIUM", "LOW"):
            continue
        if is_ssh:
            decoded = decode_ssh_alg(item)
            if not decoded:
                decoded = _fallback_alg(item)
            if not decoded:
                continue
            canon, cat, weak_flag = decoded
            res = classify(canon)
            if res:
                sink.append(_config_finding(system, rel, line_no, item, canon, res[1],
                                            cat, Confidence.HIGH, ctx_line))
            continue
        # TLS 套件
        components = decode_tls_suite(item)
        if not components:
            # 不是套件名时，尝试把值当作独立算法名（如 signature_hash: sha1）
            fb = _fallback_alg(item)
            components = [fb] if fb else []
        for canon, cat, weak_flag in components:
            res = classify(canon)
            if res:
                sink.append(_config_finding(system, rel, line_no, item, canon, res[1],
                                            cat, Confidence.HIGH, ctx_line))


def _fallback_alg(name: str) -> tuple[str, str, bool] | None:
    res = classify(name)
    if not res:
        return None
    canon, info = res
    return canon, info.category, info.weak


def scan_config(root: Path, system: str) -> list[Finding]:
    sink: list[Finding] = []
    # 配置扫描只看配置文件，避免把 .go/.py 源码里的常量当套件配置
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            ext = p.suffix.lower()
            name_l = fn.lower()
            is_config = ext in CONFIG_EXT or any(h in name_l for h in CONFIG_NAME_HINTS)
            if not is_config:
                continue
            try:
                if p.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(p.relative_to(root))
            _parse_config_text(system, rel, text, sink)
    # 去重
    uniq: dict[tuple, Finding] = {}
    for f in sink:
        k = (f.file_path, f.line, f.algorithm, f.variant_raw)
        uniq.setdefault(k, f)
    return list(uniq.values())


# 行内列表/标量值：key: value 或 key = value 或 key value（sshd/nginx 风格）
_KV_RE = re.compile(r'^["\']?([\w.\-]+)["\']?\s*[:=]\s*(.*?)\s*,?$')
_KV_SPACE_RE = re.compile(r"^([\w.\-]+)\s+(.+)$")
_LIST_ITEM_RE = re.compile(r"^\s*-\s*['\"]?([^'\"\s#][^'\"#]*)['\"]?\s*,?$")


def _strip_inline_comment(s: str) -> str:
    # 引号内的 # 不当注释；配置里套件名不含 #，简单处理
    in_quote = None
    for i, ch in enumerate(s):
        if ch in ("'", '"'):
            in_quote = None if in_quote == ch else (in_quote or ch)
        if ch == "#" and in_quote is None and i > 0 and s[i - 1] in " \t":
            return s[:i]
    return s


def _parse_config_text(system: str, rel: str, text: str, sink: list) -> None:
    pending: tuple[str, str, int] | None = None  # (key, kind, line_no) 等待块内列表项
    for idx, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_inline_comment(raw_line.rstrip())
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        indent = len(line) - len(line.lstrip())

        m = _KV_RE.match(stripped) or _KV_SPACE_RE.match(stripped)
        if m:
            key, value = m.group(1), m.group(2).strip().strip("'\"")
            matched = next(((rx, k) for rx, k in _KEY_PATTERNS if rx.search(key)), None)
            if matched:
                _, kind = matched
                # 行内 JSON/YAML 风格数组：[ "a", "b" ]
                inline_items = re.findall(r"['\"]([^'\"]+)['\"]", value)
                if inline_items:
                    for item in inline_items:
                        _handle_value(system, rel, idx, key, item, kind, sink)
                    pending = (key, kind, idx)
                elif value and value not in ("|", ">"):
                    _handle_value(system, rel, idx, key, value, kind, sink)
                    pending = (key, kind, idx)
                else:
                    pending = (key, kind, idx)
                continue
        # 列表项归属最近的待处理键（YAML 块列表 / nginx 续行也由此覆盖）
        lm = _LIST_ITEM_RE.match(line)
        if lm and pending and indent >= 0:
            key, kind, pno = pending
            _handle_value(system, rel, idx, key, lm.group(1), kind, sink)
            continue
        # 缩进回到顶层且不是列表项，挂起上下文失效
        if pending and indent == 0 and not stripped.startswith("-"):
            pending = None
