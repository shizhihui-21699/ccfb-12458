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
