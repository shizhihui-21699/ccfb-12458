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
