"""测试夹具：在 tmp_path 下构造多语言迷你仓库。"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

# 支持 python -I（隔离模式）下运行：显式注入项目根目录
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pytest


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "demo-system"
    root.mkdir()

    (root / "py").mkdir()
    (root / "py" / "a.py").write_text(textwrap.dedent('''
        import hashlib, random, jwt
        from Crypto.Cipher import AES
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def f1(x): return hashlib.md5(x).hexdigest()
        def f2(x): return hashlib.new("sha1", x).hexdigest()
        def f3(x): return hashlib.sha256(x).hexdigest()
        def f4(key, data):
            c = AES.new(key, AES.MODE_ECB)
            return c.encrypt(data)
        def f5(key, iv, data):
            return Cipher(algorithms.AES(key), modes.GCM(iv))
        def f6(): return random.randint(0, 9)
        def f7(c): return jwt.encode(c, "", algorithm="none")
        # 注释里的 md5 不应被识别
        # hashlib.md5(b"comment")
    '''), encoding="utf-8")

    (root / "jv").mkdir()
    (root / "jv" / "B.java").write_text(textwrap.dedent('''
        import javax.crypto.Cipher;
        import java.security.MessageDigest;
        public class B {
            void x() throws Exception {
                MessageDigest.getInstance("MD5");
                Cipher.getInstance("AES/CBC/PKCS5Padding");
                Cipher.getInstance("DESede/ECB/PKCS5Padding");
            }
        }
    '''), encoding="utf-8")

    (root / "go").mkdir()
    (root / "go" / "c.go").write_text(textwrap.dedent('''
        package main
        import ("crypto/md5"; "math/rand")
        func h(d []byte) string { h := md5.New(); h.Write(d); return "" }
        func r() int { return rand.Intn(10) }
    '''), encoding="utf-8")

    (root / "js").mkdir()
    (root / "js" / "d.js").write_text(textwrap.dedent('''
        const crypto = require("crypto");
        crypto.createHash("sha1");
        crypto.createCipheriv("des-ede3-cbc", k, iv);
        Math.random();
    '''), encoding="utf-8")

    (root / "c").mkdir()
    (root / "c" / "e.c").write_text(textwrap.dedent('''
        #include <openssl/evp.h>
        void f() {
            EVP_MD_CTX *c = EVP_MD_CTX_new();
            EVP_DigestInit_ex(c, EVP_md5(), 0);
            EVP_EncryptInit_ex(0, EVP_aes_128_ecb(), 0, 0, 0);
            unsigned int n = (unsigned int)rand();
        }
    '''), encoding="utf-8")

    (root / "conf").mkdir()
    (root / "conf" / "nginx.conf").write_text(textwrap.dedent('''
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:RC4-MD5:ECDHE-RSA-DES-CBC3-SHA;
        ssl_ecdh_curve X25519MLKEM768:X25519;
    '''), encoding="utf-8")
    (root / "conf" / "sshd_config").write_text(textwrap.dedent('''
        Ciphers aes128-cbc,chacha20-poly1305@openssh.com
        KexAlgorithms diffie-hellman-group1-sha1,mlkem768x25519-sha256
        MACs hmac-md5,hmac-sha2-256
        HostKeyAlgorithms ssh-dss,ssh-ed25519
    '''), encoding="utf-8")
    (root / "conf" / "app.yaml").write_text(textwrap.dedent('''
        tls:
          min_version: "TLSv1.0"
          ciphers:
            - "TLS_RSA_WITH_AES_128_CBC_SHA"
            - "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
    '''), encoding="utf-8")
    return root
