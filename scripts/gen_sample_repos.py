#!/usr/bin/env python3
"""生成四个样例系统的源码与配置（每个系统风险水平不同，含同一算法的多种写法）。"""
from __future__ import annotations

import pathlib
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1] / "samples"


def w(rel: str, content: str) -> None:
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


# ============================================================
# 1. legacy-payment-gateway：重灾区（critical 集中）
# ============================================================
def legacy_payment() -> None:
    s = "legacy-payment-gateway"
    w(f"{s}/app/hashing.py", '''
        import hashlib
        import random
        from Crypto.Cipher import AES, DES3
        from Crypto.Util.Padding import pad

        def legacy_password_hash(pwd: str) -> str:
            # 写法 1：直接调用 hashlib.md5
            return hashlib.md5(pwd.encode()).hexdigest()

        def file_fingerprint(blob: bytes) -> str:
            # 写法 2：hashlib.new 间接构造 MD5
            h = hashlib.new("md5")
            h.update(blob)
            return h.hexdigest()

        def token_signature(payload: str) -> str:
            # 写法 3：SHA1 + 弱随机数
            salt = str(random.randint(1000, 9999))
            return hashlib.sha1((payload + salt).encode()).hexdigest()

        def encrypt_card_data(plaintext: bytes, key: bytes) -> bytes:
            # ECB 模式（pycryptodome 写法）
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.encrypt(pad(plaintext, 16))

        def triple_des_wrap(dek: bytes, keks: bytes) -> bytes:
            cipher = DES3.new(keks, DES3.MODE_ECB)
            return cipher.encrypt(dek)
    ''')
    w(f"{s}/app/PaymentCipher.java", '''
        package com.example.pay;
        import javax.crypto.Cipher;
        import javax.crypto.spec.SecretKeySpec;
        import java.security.MessageDigest;
        import java.security.SecureRandom;
        import java.util.Random;

        public class PaymentCipher {
            public static String digest(String input) throws Exception {
                // 写法 4：Java JCE 的 MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
                return HexFormat.of().formatHex(md.digest(input.getBytes()));
            }

            public static byte[] desEncrypt(byte[] key, byte[] data) throws Exception {
                // Java 变换串：DESede/ECB
                Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
                return c.doFinal(data);
            }

            public static String weakToken() {
                Random r = new Random();   // java.util.Random 用于安全令牌
                return "tok-" + r.nextInt();
            }

            public static byte[] rsaWrap(byte[] kek, java.security.PublicKey pub) throws Exception {
                Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                c.init(Cipher.WRAP_MODE, pub);
                return c.wrap(new SecretKeySpec(kek, "AES"));
            }
        }
    ''')
    w(f"{s}/app/migrate_legacy.go", '''
        package main
        import (
            "crypto/md5"
            "crypto/sha1"
            "crypto/des"
            "math/rand"
            "encoding/hex"
        )

        // 写法 5：Go 的 md5.New
        func legacyChecksum(data []byte) string {
            h := md5.New()
            h.Write(data)
            return hex.EncodeToString(h.Sum(nil))
        }

        func sha1Mac(data []byte) string {
            h := sha1.New()
            h.Write(data)
            return hex.EncodeToString(h.Sum(nil))
        }

        func desBlock(key []byte) (cipher.Block, error) {
            return des.NewCipher(key) // 单倍 DES
        }

        func sessionId() int {
            return rand.Intn(1000000) // math/rand 用于会话 ID
        }
    ''')
    w(f"{s}/app/jwt_util.js", '''
        const crypto = require("crypto");
        const jwt = require("jsonwebtoken");

        // 写法 6：Node.js createHash md5
        function checksum(buf) {
            return crypto.createHash("md5").update(buf).digest("hex");
        }
        // 写法 7：createCipheriv + DES-EDE3-CBC（OpenSSL 命名）
        function encrypt3des(key, iv, data) {
            const c = crypto.createCipheriv("des-ede3-cbc", key, iv);
            return Buffer.concat([c.update(data), c.final()]);
        }
        function forgeToken(payload, key) {
            return jwt.sign(payload, key, { algorithm: "none" }); // alg=none
        }
        function randomish() { return Math.random().toString(36); }
        module.exports = { checksum, encrypt3des, forgeToken, randomish };
    ''')
    w(f"{s}/nginx/nginx.conf", '''
        worker_processes 1;
        http {
            server {
                listen 443 ssl;
                server_name pay.example.com;
                ssl_certificate     /etc/ssl/pay-legacy-sha1.crt;
                ssl_certificate_key /etc/ssl/pay-legacy-rsa1024.key;
                ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
                ssl_ciphers "ECDHE-RSA-DES-CBC3-SHA:AES128-SHA:ECDHE-RSA-AES128-SHA256:RC4-MD5:!aNULL";
                ssl_prefer_server_ciphers on;
            }
        }
    ''')
    w(f"{s}/deploy/sshd_config", '''
        Port 22
        PermitRootLogin yes
        Ciphers aes128-cbc,3des-cbc,arcfour,aes128-ctr
        KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256
        MACs hmac-md5,hmac-sha1,hmac-sha2-256
        HostKeyAlgorithms ssh-dss,ssh-rsa,rsa-sha2-256
    ''')
    w(f"{s}/app/application.properties", '''
        server.ssl.enabled-protocols=TLSv1,TLSv1.1,TLSv1.2
        server.ssl.ciphers=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_RC4_128_MD5
        signing.algorithm=SHA1withRSA
        digest.name=MD5
    ''')


# ============================================================
# 2. internal-portal：中等（有弱用法但也有现代配置）
# ============================================================
def internal_portal() -> None:
    s = "internal-portal"
    w(f"{s}/portal/auth.py", '''
        import hashlib
        import hmac
        import secrets
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def password_hash(pwd: str, salt: bytes) -> bytes:
            # PBKDF2-HMAC-SHA256：合规 KDF，但底层哈希未来需评估升级
            return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 120_000)

        def request_signature(secret: bytes, body: bytes) -> str:
            return hmac.new(secret, body, hashlib.sha256).hexdigest()

        def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
            # CBC 非 AEAD，存在填充 oracle 风险
            c = Cipher(algorithms.AES(key), modes.CBC(iv))
            enc = c.encryptor()
            return enc.update(plaintext) + enc.finalize()

        def reset_token() -> str:
            return secrets.token_urlsafe(32)  # CSPRNG，正确用法
    ''')
    w(f"{s}/portal/SsoToken.java", '''
        package com.example.portal;
        import java.security.Signature;
        import java.security.KeyPairGenerator;

        public class SsoToken {
            public static Signature rs256() throws Exception {
                // RSASSA-PKCS1-v1_5 + SHA-256：经典安全，PQ 风险在 RSA 本身
                return Signature.getInstance("SHA256withRSA");
            }
            public static KeyPairGenerator rsaKey() throws Exception {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                return kpg;
            }
        }
    ''')
    w(f"{s}/portal/tls.go", '''
        package main
        import (
            "crypto/ecdsa"
            "crypto/elliptic"
            "crypto/rand"
            "crypto/tls"
        )

        func tlsConfig() *tls.Config {
            priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
            _ = priv
            return &tls.Config{
                MinVersion: tls.VersionTLS12,
                CipherSuites: []uint16{
                    tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // CBC 套件
                    tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                },
            }
        }
    ''')
    w(f"{s}/config/nginx-portal.conf", '''
        server {
            listen 443 ssl;
            server_name portal.internal.example.com;
            ssl_certificate     /ssl/portal.crt;
            ssl_certificate_key /ssl/portal-ec.key;
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA;
            ssl_conf_command Ciphers ECDHE-ECDSA-AES128-GCM-SHA256;
            ssl_ecdh_curve secp256r1;
        }
    ''')
    w(f"{s}/config/sshd_config", '''
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr
        KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
        MACs hmac-sha2-256,hmac-sha2-512
        HostKeyAlgorithms ssh-ed25519,rsa-sha2-256,ecdsa-sha2-nistp256
    ''')
    w(f"{s}/config/appsettings.json", '''
        {
          "Kestrel": {
            "ConfigureHttpsDefaults": {
              "SslProtocols": "TLS12, TLS13",
              "CipherSuitesPolicy": [
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
              ]
            }
          }
        }
    ''')


# ============================================================
# 3. iot-firmware：critical 最密集 + C/嵌入式
# ============================================================
def iot_firmware() -> None:
    s = "iot-firmware"
    w(f"{s}/src/crypto_hal.c", '''
        #include <openssl/evp.h>
        #include <openssl/md5.h>
        #include <openssl/des.h>
        #include <stdlib.h>

        int firmware_hash(const unsigned char *buf, int len, unsigned char *out) {
            // OpenSSL EVP MD5
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
            EVP_DigestUpdate(ctx, buf, len);
            unsigned int outlen;
            EVP_DigestFinal_ex(ctx, out, &outlen);
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        int rf_encrypt(const unsigned char *key, unsigned char *in, int len) {
            // DES-EDE3-ECB 硬件兼容模式
            EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(c, EVP_des_ede3_ecb(), NULL, key, NULL);
            int outl;
            EVP_EncryptUpdate(c, NULL, &outl, in, len);
            EVP_CIPHER_CTX_free(c);
            return 0;
        }

        unsigned int weak_nonce(void) {
            return (unsigned int)rand(); /* libc rand 当 nonce */
        }
    ''')
    w(f"{s}/src/ota.cpp", '''
        #include <openssl/sha.h>
        #include <openssl/evp.h>
        void ota_digest(const unsigned char *p, int n, unsigned char *out) {
            SHA1(p, n, out); // 裸 SHA1 接口
        }
        void aes_ecb_legacy(const unsigned char *key, const unsigned char *in, unsigned char *out) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
            int l; EVP_EncryptUpdate(ctx, out, &l, in, 16);
            EVP_CIPHER_CTX_free(ctx);
        }
    ''')
    w(f"{s}/src/provisioning.py", '''
        import hashlib
        import jwt

        def device_password_hash(secret: str) -> str:
            return hashlib.sha1(secret.encode()).hexdigest()

        def make_device_token(claims: dict) -> str:
            # 设备端 JWT 关闭签名
            return jwt.encode(claims, "", algorithm="none")

        def md5_mac(msg: bytes) -> str:
            return hashlib.new("MD5", data=msg).hexdigest()
    ''')
    w(f"{s}/firmware/config.yaml", '''
        security:
          tls:
            min_version: "TLSv1.0"
            ciphers:
              - "TLS_RSA_WITH_AES_128_CBC_SHA"
              - "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
              - "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
          ssh:
            kex: ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"]
            hostkey: ["ssh-dss", "ssh-rsa"]
            mac: ["hmac-md5", "hmac-sha1"]
        firmware:
          signature_hash: "sha1"
    ''')


# ============================================================
# 4. data-pipeline：现代化 + PQ 试点（ready 方向）
# ============================================================
def data_pipeline() -> None:
    s = "data-pipeline"
    w(f"{s}/pipeline/crypto_service.py", '''
        """统一加密服务：算法配置化（crypto-agility 证据），并含 PQ 试点。"""
        import hashlib
        import secrets
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        def encrypt_aesgcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
            return AESGCM(key).encrypt(nonce, plaintext, aad)

        def encrypt_chacha(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
            return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

        def kdf(pw: str, salt: bytes) -> bytes:
            return hashlib.pbkdf2_hmac("sha384", pw.encode(), salt, 200_000)

        def token() -> str:
            return secrets.token_urlsafe(48)

        # ---- 后量子试点：ML-KEM-768 封装（通过 pqcrypto 试点库）----
        def pq_seal(peer_pq_pubkey: bytes, plaintext: bytes) -> bytes:
            from pqcrypto.kem import mlkem768  # 试点依赖，生产环境待 FIPS 203 库成熟
            ciphertext, shared = mlkem768.encrypt(peer_pq_pubkey)
            return ciphertext
    ''')
    w(f"{s}/pipeline/signing.rs", '''
        use sha2::{Sha384, Digest};
        use ed25519_dalek::SigningKey;
        // use pqcrypto_dilithium::ml_dsa_65; // 路线图：ML-DSA-65 替换 Ed25519

        pub fn digest(data: &[u8]) -> Vec<u8> {
            let mut h = Sha384::new();
            h.update(data);
            h.finalize().to_vec()
        }

        pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
            key.sign(msg).to_bytes().to_vec()
        }
    ''')
    w(f"{s}/pipeline/tls_config.go", '''
        package main
        import "crypto/tls"

        func modernTLS() *tls.Config {
            return &tls.Config{
                MinVersion: tls.VersionTLS13,
                CipherSuites: []uint16{
                    tls.TLS_AES_256_GCM_SHA384,
                    tls.TLS_CHACHA20_POLY1305_SHA256,
                },
                // TLS 1.3 混合后量子组（试点）
                CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
            }
        }
    ''')
    w(f"{s}/deploy/gateway.conf", '''
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
        ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
        ssl_conf_command Groups X25519MLKEM768:X25519;
    ''')
    w(f"{s}/deploy/sshd_config", '''
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
        KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,sntrup761x25519-sha512@openssh.com
        MACs hmac-sha2-512
        HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp384
    ''')
    w(f"{s}/pipeline/pq_roadmap.md", '''
        # 后量子迁移路线图
        - 2026Q2: ML-KEM-768 试点环境验证（内部服务 mTLS 混合握手）
        - 2026Q3: ML-DSA-65 签名服务灰度，替换 Ed25519 令牌签名
        - 2027Q1: 全量 TLS 启用 X25519MLKEM768 混合组
        - 对称侧保持 AES-256-GCM / ChaCha20-Poly1305，哈希统一切 SHA-384
    ''')


if __name__ == "__main__":
    legacy_payment()
    internal_portal()
    iot_firmware()
    data_pipeline()
    print("样例仓库已生成到", ROOT)
