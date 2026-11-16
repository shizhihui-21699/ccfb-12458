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
