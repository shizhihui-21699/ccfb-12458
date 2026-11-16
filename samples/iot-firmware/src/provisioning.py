import hashlib
import jwt

def device_password_hash(secret: str) -> str:
    return hashlib.sha1(secret.encode()).hexdigest()

def make_device_token(claims: dict) -> str:
    # 设备端 JWT 关闭签名
    return jwt.encode(claims, "", algorithm="none")

def md5_mac(msg: bytes) -> str:
    return hashlib.new("MD5", data=msg).hexdigest()
