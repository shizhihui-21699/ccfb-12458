"""源码加密调用扫描器。

识别策略（三层）：
1. Python：AST 结构化识别（hashlib.new('md5')、Crypto.Cipher.AES.new(..., MODE_ECB) 等各种写法）
2. 语言专属正则：Java/Go/JS/TS/C/C++ 的加密 API 调用（含字符串字面量与变换串解析）
3. 通用 token 兜底：任何文件中的算法名 token（低置信度），跳过英语常用词误报

"同一处用法换个写法也认得出" 依赖 catalog.classify 的别名归一化 + 变换串拆分，
例如 hashlib.md5 / hashlib.new('md5') / MessageDigest.getInstance("MD5") /
crypto.createHash('md5') / md5sum 最终都归到 MD5。
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from ..models import AssetType, Confidence, Finding, Severity
from ..rules.catalog import AlgInfo, classify, split_java_cipher

# ---------------------------------------------------------------- 常量

LANG_BY_EXT = {
    ".py": "python",
    ".java": "java",
    ".kt": "java",
    ".go": "go",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
}
SCANNABLE_EXT = set(LANG_BY_EXT)
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".idea",
             ".mypy_cache", ".pytest_cache", "dist", "build", "target", "vendor",
             ".tox", ".eggs", "egg-info"}
MAX_FILE_BYTES = 2 * 1024 * 1024

# 通用 token 兜底时的英语常用词 / 明显非算法白名单
TOKEN_STOPWORDS = {
    "RANDOM", "RAND", "HASH", "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "CIPHER",
    "KEY", "SECRET", "TOKEN", "PASSWORD", "CERT", "CERTIFICATE", "SECURE",
    "DIGEST", "MAC", "MODE", "PADDING", "BLOCK", "STREAM", "ALGORITHM", "ALGO",
    "AES-GCM",  # 由 AES 正则处理，避免重复
}

# ----------------------------------------------------------- 语言正则规则
# 每条: (rule_id, 编译正则, 取值组名/组号, 语言集合)

def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


REGEX_RULES: list[tuple[str, re.Pattern, str, set[str]]] = [
    # ---------- 哈希 ----------
    ("java-message-digest",
     _rx(r"MessageDigest\s*\.\s*getInstance\s*\(\s*['\"]([A-Za-z0-9\-]+)['\"]"), 1, {"java"}),
    ("java-mac",
     _rx(r"Mac\s*\.\s*getInstance\s*\(\s*['\"]([A-Za-z0-9\-]+)['\"]"), 1, {"java"}),
    ("go-hash",
     _rx(r"\b(md5|sha1|sha256|sha512|sha512_256|sha3_256|ripemd160)\s*\.\s*New\b"), 1, {"go"}),
    ("go-hash-crypto",
     _rx(r"crypto\s*\.\s*(md5|sha1|sha256|sha512)\b"), 1, {"go"}),
    ("go-hash-import",
     _rx(r'"crypto/(md5|sha1|sha256|sha512|sha512_256|sha3_256|ripemd160)"'), 1, {"go"}),
    ("go-cipher-import", _rx(r'"crypto/(des|aes|cipher)"'), 1, {"go"}),
    ("js-createhash",
     _rx(r"createHash\s*\(\s*['\"`]([A-Za-z0-9\-]+)['\"`]"), 1, {"js"}),
    ("js-createhmac",
     _rx(r"createHmac\s*\(\s*['\"`]([A-Za-z0-9\-]+)['\"`]"), 1, {"js"}),
    ("ruby-digest",
     _rx(r"Digest[::](MD5|SHA1|SHA256|SHA384|SHA512|RMD160)\b"), 1, {"ruby"}),
    ("php-hash",
     _rx(r"\bhash\s*\(\s*['\"](md5|sha1|sha256|sha384|sha512|ripemd160)['\"]"), 1, {"php"}),
    ("php-md5-sha1-fn",
     _rx(r"\b(md5|sha1)\s*\("), 1, {"php"}),
    ("cs-hashalgorithm",
     _rx(r"HashAlgorithm(?:Name)?\s*\.\s*(Create\s*\(\s*['\"]([A-Za-z0-9\-]+)['\"]|(MD5|SHA1|SHA256|SHA384|SHA512))"),
     None, {"csharp"}),
    ("rust-digest",
     _rx(r"(Md5|Sha1|Sha256|Sha384|Sha512|Sha3_256)\s*::"), 1, {"rust"}),
    # ---------- 通用 API 名（python 兜底正则也覆盖，AST 失败时使用）----------
    ("py-hashlib-fn",
     _rx(r"hashlib\s*\.\s*(md5|sha1|sha224|sha256|sha384|sha512|blake2[bs]|sha3_\d+)\s*\("), 1, {"python"}),
    ("py-hashlib-new",
     _rx(r"hashlib\s*\.\s*new\s*\(\s*['\"]([A-Za-z0-9\-]+)['\"]"), 1, {"python"}),
    # ---------- 对称：变换串 ----------
    ("java-cipher",
     _rx(r"Cipher\s*\.\s*getInstance\s*\(\s*['\"]([A-Za-z0-9]+(?:/[A-Za-z0-9]+){1,2})['\"]"), 1, {"java"}),
    ("js-createcipher",
     _rx(r"createCipher(?:iv)?\s*\(\s*['\"`]([A-Za-z0-9\-/]+)['\"`]"), 1, {"js"}),
    ("py-cryptodome-cipher",
     _rx(r"\b(?:DES|DES3|AES|Blowfish|ARC4|ChaCha20)\s*\.\s*new\s*\(([^)]*)\)"), 1, {"python"}),
    ("py-cryptography-cipher",
     _rx(r"Cipher\s*\(\s*algorithms\s*\.\s*([A-Za-z0-9_]+)\s*\("), 1, {"python"}),
    ("py-cryptography-modes",
     _rx(r"modes\s*\.\s*(ECB|CBC|GCM|CTR|CCM|OFB|CFB|XTS)\s*\("), 1, {"python"}),
    ("go-cipher-block",
     _rx(r"(aes|des|tripledes)\s*\.\s*NewCipher\b"), 1, {"go"}),
    ("openssl-evp",
     _rx(r"EVP_((?:aes|des|rc4|chacha)[0-9a-z_]*(?:ecb|cbc|gcm|ctr|ccm|ofb|cfb)?)\s*\("), 1, {"c", "cpp"}),
    ("openssl-evp-digest-fn",
     _rx(r"EVP_(md5|sha1|sha224|sha256|sha384|sha512|sha3_256)\s*\("), 1, {"c", "cpp"}),
    ("openssl-lowhash", _rx(r"\b(MD5|SHA1|SHA256|SHA384|SHA512)\s*\("), 1, {"c", "cpp"}),
    ("cs-symmetric",
     _rx(r"(Aes|DES|TripleDES|RC4|Rijndael)\s*\.\s*Create\b"), 1, {"csharp"}),
    # ---------- 非对称 ----------
    ("java-keypair",
     _rx(r"KeyPairGenerator\s*\.\s*getInstance\s*\(\s*['\"](RSA|DSA|EC|Ed25519|X25519|ML-KEM[A-Za-z0-9\-]*)['\"]"), 1, {"java"}),
    ("java-signature",
     _rx(r"Signature\s*\.\s*getInstance\s*\(\s*['\"]([A-Za-z0-9]+with[A-Za-z0-9]+)['\"]"), 1, {"java"}),
    ("go-rsa", _rx(r"\brsa\s*\.\s*(GenerateKey|EncryptOAEP|SignPKCS1v15|SignPSS)\b"), "RSA", {"go"}),
    ("go-ecdsa", _rx(r"\becdsa\s*\.\s*(GenerateKey|SignASN1|VerifyASN1)\b"), "ECDSA", {"go"}),
    ("go-ed25519", _rx(r"\bed25519\s*\.\s*GenerateKey\b"), "ED25519", {"go"}),
    ("go-ecdh", _rx(r"\becdh\s*\.\s*(X25519|P256|P384|P521)\(\)"), "ECDH", {"go"}),
    ("js-webcrypto",
     _rx(r"(?:generateKey|importKey)\s*\(\s*\{[^\}]*name\s*:\s*['\"]([A-Za-z0-9\-]+)['\"]"), 1, {"js"}),
    ("py-cryptography-asym",
     _rx(r"asymmetric\s*\.\s*(rsa|ec|ed25519|x25519|dsa)\s*\."), 1, {"python"}),
    ("rust-rustls-ring",
     _rx(r"(Rsa|Ecdsa|Ed25519|X25519|MlKem[A-Za-z0-9]*)\s*::"), 1, {"rust"}),
    # ---------- KDF / 口令 ----------
    ("py-pbkdf2", _rx(r"hashlib\s*\.\s*pbkdf2_hmac\s*\(\s*['\"]([A-Za-z0-9]+)['\"]"), 1, {"python"}),
    ("java-secretkeyfactory",
     _rx(r"SecretKeyFactory\s*\.\s*getInstance\s*\(\s*['\"](PBKDF2[A-Za-z0-9]*|BCrypt|SCrypt)['\"]"), 1, {"java"}),
    ("bcrypt-lib", _rx(r"\b(bcrypt|argon2|scrypt)\s*\.\s*(hash|hashpw|verify|kdf)\b"), 1, {"python", "js", "ruby", "go", "java"}),
    # ---------- 弱随机数 ----------
    ("py-random", _rx(r"(?<!secrets\.)(?<!SystemRandom)\brandom\s*\.\s*(random|randint|choice|randrange|getrandbits)\s*\("),
     "INSECURE-RNG", {"python"}),
    ("js-math-random", _rx(r"Math\s*\.\s*random\s*\("), "INSECURE-RNG", {"js"}),
    ("java-util-random", _rx(r"new\s+Random\s*\("), "INSECURE-RNG", {"java", "csharp"}),
    ("go-math-rand-import", _rx(r'"math/rand"'), "INSECURE-RNG", {"go"}),
    # 裸 rand. 调用是否安全取决于 import（math/rand 弱，crypto/rand 安全），
    # 仅当文件未导入 crypto/rand 时由 scan_file 中的 Go 专项逻辑判定
    ("go-rand-call-candidate", _rx(r"(?<![A-Za-z0-9_./])rand\s*\.\s*(Intn|Int31|Int63|Float64|New|Seed|Shuffle)\s*\("),
     "INSECURE-RNG", {"go"}),
    ("c-librand", _rx(r"(?<![A-Za-z0-9_])(?:rand|random|lrand48|drand48)\s*\(\s*\)"), "INSECURE-RNG", {"c", "cpp"}),
    ("ruby-insecure-rand", _rx(r"(?<!SecureRandom\.)\brand\s*\("), "INSECURE-RNG", {"ruby"}),
    ("php-mt-rand", _rx(r"\b(mt_rand|rand)\s*\("), "INSECURE-RNG", {"php"}),
    # ---------- JWT ----------
    ("jwt-none", _rx(r"alg\s*:\s*['\"](?:none|None|NONE)['\"]"), "JWT-NONE",
     {"python", "java", "go", "js", "ruby", "php", "csharp", "rust"}),
    ("jwt-alg", _rx(r"jwt[._a-zA-Z]*\s*(?:encode|sign)\s*\([^)]*algorithm\s*=\s*['\"]([A-Z]{2}\d{3}|none)['\"]"), 1, {"python"}),
]

# 通用 token 兜底：捕捉引号/反引号里或独立出现的算法名
TOKEN_RE = re.compile(
    r"(?<![A-Z0-9])"
    r"((?:ML-?(?:KEM|DSA)-\d{2,4}|MLKEM\d{3,4}(?:X25519)?|SNTRUP\d+|FALCON-?\d+|HQC-\d+|"
    r"SHA-?\d{2,3}(?:/\d{3})?|SHA3-?\d{3}|SHA1|SHA-?1|MD[245]|RIPEMD-?160|"
    r"AES-?\d{3}(?:-?(?:ECB|CBC|GCM|CCM|CTR|OFB|CFB|XTS))?|"
    r"3DES|DES-EDE3|TRIPLEDES|CHACHA20(?:-POLY1305)?|RC4|BLOWFISH|"
    r"RSA-?\d{3,5}|ECDSA(?:-?P-?\d+)?|ED25519|X25519|ED448|X448|"
    r"PBKDF2(?:-HMAC-SHA\d+)?|ARGON2(?:ID|I|D)?|SCRYPT|BCRYPT|HKDF))"
    r"(?![A-Z0-9])",
    re.IGNORECASE,
)

# 混合组：X25519MLKEM768 这类标识符整体是一个 PQ 混合组，不能被切成 X25519+MLKEM768
HYBRID_GROUP_RE = re.compile(
    r"(?<![A-Z0-9])((?:X25519|X448|SECP256R1|SECP384R1)MLKEM(?:512|768|1024)|"
    r"MLKEM(?:512|768|1024)(?:X25519|X448)?|SNTRUP\d{3,4}X25519)(?![A-Z0-9])",
    re.IGNORECASE,
)

# 各语言注释：行注释前缀（块注释在 _strip_comments 中处理）
_LINE_COMMENT = {"python": "#", "ruby": "#", "php": "#", "java": "//", "go": "//",
                 "js": "//", "c": "//", "cpp": "//", "csharp": "//", "rust": "//"}
_BLOCK_COMMENTS = (("/*", "*/"),)


def _strip_comments(text: str, language: str) -> str:
    """把注释内容替换为等长空白（保留行号与列偏移），字符串保留。"""
    out = list(text)
    n = len(out)
    i = 0
    quote = None
    line_prefix = _LINE_COMMENT.get(language)
    while i < n:
        ch = out[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and out[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if line_prefix and text.startswith(line_prefix, i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if language == "python" and ch == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)

# --------------------------------------------------------------- 工具函数


def _make_finding(system: str, language: str, path: Path, rel: str, line_no: int,
                  raw: str, rule_id: str, confidence: Confidence,
                  result: tuple[str, AlgInfo], context: str = "",
                  asset_type: AssetType = AssetType.CODE, extra: dict | None = None) -> Finding:
    canonical, info = result
    return Finding(
        system=system, asset_type=asset_type, language=language,
        file_path=rel, line=line_no, algorithm=canonical, category=info.category,
        variant_raw=raw[:200], rule_id=rule_id, confidence=confidence,
        severity=Severity(info.severity), weak=info.weak,
        pq_status=info.pq_status, pq_note=info.pq_note,
        context=context.strip()[:300], extra=extra or {},
    )


def _emit(system: str, language: str, path: Path, rel: str, line_no: int,
          raw: str, rule_id: str, confidence: Confidence, context: str,
          sink: list[Finding], key_bits: int | None = None) -> None:
    """对一个原始算法名做归一化并产出 Finding（可产出多条，如变换串）。"""
    # Java 风格变换串
    if "/" in raw and re.match(r"^[A-Za-z0-9]+/[A-Za-z0-9]+(/[A-Za-z0-9]+)?$", raw.strip()):
        for sub, _ in split_java_cipher(raw):
            if sub == "__ECB_MODE__":
                res = classify("ECB-MODE")
            else:
                res = classify(sub)
            if res:
                sink.append(_make_finding(system, language, path, rel, line_no, raw,
                                          rule_id, confidence, res, context))
        return
    # 显式 ECB 模式 token（如 MODE_ECB / ECB）
    if raw.upper().replace("_", "") in ("MODEECB", "ECB"):
        sink.append(_make_finding(system, language, path, rel, line_no, raw,
                                  rule_id, confidence, classify("ECB-MODE"), context))
        return
    res = classify(raw, key_bits=key_bits)
    if res:
        sink.append(_make_finding(system, language, path, rel, line_no, raw,
                                  rule_id, confidence, res, context))


# --------------------------------------------------------------- Python AST

class _PythonAstVisitor(ast.NodeVisitor):
    """结构化识别 Python 加密调用，覆盖 hashlib / hmac / cryptography / pycryptodome /
    jwt / random / secrets / pyca 等主流库的多种写法。"""

    def __init__(self, system: str, path: Path, rel: str, source_lines: list[str],
                 sink: list[Finding]):
        self.system, self.path, self.rel, self.lines, self.sink = system, path, rel, source_lines, sink
        self.lang = "python"

    def _line(self, node: ast.AST) -> int:
        return getattr(node, "lineno", 0)

    def _ctx(self, node: ast.AST) -> str:
        ln = self._line(node)
        return self.lines[ln - 1] if 0 < ln <= len(self.lines) else ""

    def _const_str(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _attr_chain(self, node: ast.AST) -> str:
        """还原 a.b.c 形式的调用链。"""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        chain = self._attr_chain(node.func)
        chain_l = chain.lower()
        ctx = self._ctx(node)
        ln = self._line(node)

        # hashlib.md5() / hashlib.sha256() ...
        m = re.match(r"hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|blake2[bs]|sha3_\d+)$", chain_l)
        if m:
            self._emit(ln, m.group(1), "py-ast-hashlib-fn", ctx)
        # hashlib.new('md5', ...) / hashlib.new(name='sha1')
        if chain_l == "hashlib.new":
            name = self._arg_str(node, 0) or self._kwarg_str(node, "name")
            if name:
                self._emit(ln, name, "py-ast-hashlib-new", ctx)
        # hashlib.pbkdf2_hmac('sha256', ...)
        if chain_l == "hashlib.pbkdf2_hmac":
            name = self._arg_str(node, 0) or self._kwarg_str(node, "hash_name")
            if name:
                self._emit(ln, f"PBKDF2-{name}", "py-ast-pbkdf2", ctx)
        # hmac.new(key, msg, 'sha256') / hmac.new(..., digestmod=hashlib.sha256)
        if chain_l in ("hmac.new",):
            name = self._kwarg_str(node, "digestmod") or self._arg_str(node, 2)
            if name:
                self._emit(ln, f"HMAC-{name}", "py-ast-hmac", ctx)
            elif len(node.args) >= 3 and isinstance(node.args[2], ast.Attribute):
                self._emit(ln, f"HMAC-{node.args[2].attr}", "py-ast-hmac", ctx)
        # cryptography: Cipher(algorithms.AES(key), modes.ECB())
        if chain_l == "cipher":
            self._handle_cryptography_cipher(node, ctx)
        # pycryptodome: AES.new(key, AES.MODE_ECB) / DES3.new(...)
        m2 = re.match(r"(AES|DES|DES3|Blowfish|ARC4|ChaCha20)\.new$", chain)
        if m2:
            self._handle_pycryptodome(node, m2.group(1), ctx)
        # cryptography 非对称密钥生成
        if re.search(r"asymmetric\.(rsa|ec|ed25519|x25519|dsa)\.generate", chain_l):
            alg = chain_l.split("asymmetric.")[1].split(".")[0]
            self._emit(ln, {"ec": "ECDSA"}.get(alg, alg.upper()), "py-ast-asym-gen", ctx)
        # cryptography 私钥加载（rsa/ec/ed25519/x25519/dsa/...）
        m3 = re.search(r"serialization\.load_pem_private_key", chain_l)
        if m3:
            self._emit(ln, "RSA", "py-ast-key-load", ctx, Confidence.LOW)
        # jwt.encode(..., algorithm='HS256' / 'none')
        if "jwt.encode" in chain_l or "jwt.decode" in chain_l:
            alg = self._kwarg_str(node, "algorithm")
            if alg:
                self._emit(ln, "JWT-NONE" if alg.lower() == "none" else f"JWT-{alg}",
                           "py-ast-jwt", ctx)
        # 弱随机数
        if re.match(r"random\.(random|randint|choice|randrange|getrandbits|uniform|shuffle)$", chain_l):
            self._emit(ln, "INSECURE-RNG", "py-ast-weak-rng", ctx)
        # bcrypt / argon2 / hashlib.scrypt
        if chain_l in ("bcrypt.hashpw", "bcrypt.checkpw"):
            self._emit(ln, "BCRYPT", "py-ast-kdf", ctx)
        if "argon2" in chain_l and ("hash" in chain_l or "verify" in chain_l):
            self._emit(ln, "ARGON2", "py-ast-kdf", ctx)
        if chain_l == "hashlib.scrypt":
            self._emit(ln, "SCRYPT", "py-ast-kdf", ctx)

        self.generic_visit(node)

    def _handle_cryptography_cipher(self, node: ast.Call, ctx: str) -> None:
        ln = self._line(node)
        if not node.args:
            return
        alg_call = node.args[0]
        if isinstance(alg_call, ast.Call) and isinstance(alg_call.func, ast.Attribute):
            alg_name = alg_call.func.attr  # AES / TripleDES / ChaCha20 ...
            if alg_name == "TripleDES":
                self._emit(ln, "3DES", "py-ast-cipher-alg", ctx)
            else:
                self._emit(ln, alg_name, "py-ast-cipher-alg", ctx)
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Call):
            mode_node = node.args[1]
            if isinstance(mode_node.func, ast.Attribute):
                mode = mode_node.func.attr  # ECB/CBC/GCM...
                if mode.upper() == "ECB":
                    self._emit(ln, "ECB-MODE", "py-ast-cipher-mode", ctx)
                elif mode.upper() == "CBC":
                    self._emit(ln, "AES-128-CBC", "py-ast-cipher-mode", ctx, Confidence.LOW)

    def _handle_pycryptodome(self, node: ast.Call, lib: str, ctx: str) -> None:
        ln = self._line(node)
        if lib == "DES3":
            self._emit(ln, "3DES", "py-ast-pycryptodome", ctx)
        elif lib == "DES":
            self._emit(ln, "DES", "py-ast-pycryptodome", ctx)
        elif lib == "ARC4":
            self._emit(ln, "RC4", "py-ast-pycryptodome", ctx)
        elif lib == "AES":
            self._emit(ln, "AES-128-CBC", "py-ast-pycryptodome", ctx, Confidence.LOW)
        # 第二个位置参数或 mode= 关键字给模式
        mode_val = self._kwarg_str(node, "mode")
        if not mode_val and len(node.args) >= 2:
            mode_val = self._attr_chain(node.args[1])
        if mode_val and "MODE_ECB" in mode_val.upper().replace(" ", ""):
            self._emit(ln, "ECB-MODE", "py-ast-pycryptodome-mode", ctx)
        elif mode_val and "MODE_CBC" in mode_val.upper().replace(" ", ""):
            self._emit(ln, "AES-128-CBC", "py-ast-pycryptodome-mode", ctx, Confidence.LOW)

    def _arg_str(self, node: ast.Call, idx: int) -> str | None:
        if idx < len(node.args):
            return self._const_str(node.args[idx])
        return None

    def _kwarg_str(self, node: ast.Call, key: str) -> str | None:
        for kw in node.keywords:
            if kw.arg == key:
                return self._const_str(kw.value)
        return None

    def _emit(self, line_no: int, raw: str, rule_id: str, ctx: str,
              confidence: Confidence = Confidence.HIGH) -> None:
        _emit(self.system, self.lang, self.path, self.rel, line_no, raw,
              rule_id, confidence, ctx, self.sink)


# --------------------------------------------------------------- 主扫描逻辑

def iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SCANNABLE_EXT:
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size <= MAX_FILE_BYTES:
                        yield p, ext
                except OSError:
                    continue


def scan_file(system: str, root: Path, path: Path) -> list[Finding]:
    rel = str(path.relative_to(root))
    ext = path.suffix.lower()
    lang = LANG_BY_EXT[ext]
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    # 注释剥离（行号保持不变），AST 仍用原文（注释本就不影响语法树）
    text = _strip_comments(raw_text, lang)
    lines = text.splitlines()
    # (line, algorithm) -> 当前最佳 Finding；高置信度覆盖低置信度
    best: dict[tuple, Finding] = {}
    conf_rank = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}

    def add(f: Finding) -> None:
        key = (f.line, f.algorithm)
        old = best.get(key)
        if old is None or conf_rank[f.confidence] > conf_rank[old.confidence]:
            best[key] = f

    def drain(rule_confidence: Confidence, produced: list[Finding]) -> None:
        for f in produced:
            add(f)

    # 1. Python AST（原文解析，AST 天然不包含注释内容）
    if lang == "python":
        try:
            tree = ast.parse(raw_text, filename=rel)
            ast_sink: list[Finding] = []
            _PythonAstVisitor(system, path, rel, raw_text.splitlines(), ast_sink).visit(tree)
            for f in ast_sink:
                add(f)
        except SyntaxError:
            pass  # 退化为正则

    # 2. 语言专属正则
    uses_crypto_rand = lang == "go" and re.search(r'"crypto/rand"', text) is not None
    for rule_id, rx, group, langs in REGEX_RULES:
        if lang not in langs:
            continue
        for m in rx.finditer(text):
            # Go 的裸 rand. 调用：导入了 crypto/rand 则视为安全 CSPRNG，跳过弱随机判定
            if rule_id == "go-rand-call-candidate" and uses_crypto_rand:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            ctx = lines[line_no - 1] if line_no <= len(lines) else ""
            if group is None:  # c# 多组特殊处理
                raw = next((g for g in m.groups() if g), m.group(0))
            elif isinstance(group, str) and not group.isdigit():
                raw = group  # 固定算法名（如 INSECURE-RNG / RSA）
            else:
                raw = m.group(int(group))
            if not raw:
                continue
            produced: list[Finding] = []
            _emit(system, lang, path, rel, line_no, raw, rule_id,
                  Confidence.MEDIUM, ctx, produced)
            drain(Confidence.MEDIUM, produced)

    # 3. 后量子混合组优先（X25519MLKEM768 整体识别，避免被切碎）
    hybrid_spans: list[tuple[int, int]] = []
    for m in HYBRID_GROUP_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        ctx = lines[line_no - 1] if line_no <= len(lines) else ""
        up = m.group(1).upper()
        if "MLKEM" in up:
            bits = "1024" if "1024" in up else ("512" if "512" in up else "768")
            canon = f"ML-KEM-{bits}"
            res = classify(canon)
            if res:
                add(_make_finding(system, lang, path, rel, line_no, m.group(1),
                                  "hybrid-pq-group", Confidence.MEDIUM, res, ctx,
                                  extra={"hybrid": True}))
        hybrid_spans.append(m.span())

    # 4. 通用 token 兜底（低置信度，跳过混合组区间；已存在高置信度条目时不覆盖）
    for m in TOKEN_RE.finditer(text):
        if any(s <= m.start() < e for s, e in hybrid_spans):
            continue
        raw = m.group(1)
        line_no = text.count("\n", 0, m.start()) + 1
        norm = raw.upper().replace("_", "-")
        if norm in TOKEN_STOPWORDS:
            continue
        ctx = lines[line_no - 1] if line_no <= len(lines) else ""
        produced = []
        _emit(system, lang, path, rel, line_no, raw, "generic-token",
              Confidence.LOW, ctx, produced)
        for f in produced:
            add(f)

    return list(best.values())


def scan_code(root: Path, system: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, _ in iter_source_files(root):
        findings.extend(scan_file(system, root, path))
    return findings
