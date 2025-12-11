"""
JWK 密钥管理

从环境变量读取密钥：
- JWS_KEY: Ed25519 密钥（用于签名和验签）
- JWE_KEY: A256GCM 对称密钥（用于加解密）

生成密钥：python scripts/generate_keys.py
"""
import json
import base64
from typing import Optional

from app.core.config import settings


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码（无 padding）"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Base64URL 解码（自动补 padding）"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# 缓存解析后的密钥
_jws_key: Optional[dict] = None
_jwe_key: Optional[dict] = None


def get_jws_key() -> dict:
    """获取 JWS 密钥（签名和验签都用这个）"""
    global _jws_key
    if _jws_key is None:
        if not settings.JWS_KEY:
            raise ValueError(
                "JWS_KEY 环境变量未配置。"
                "请运行 python scripts/generate_keys.py 生成密钥"
            )
        _jws_key = json.loads(settings.JWS_KEY)
    return _jws_key


def get_jwe_key() -> dict:
    """获取 JWE 密钥（加解密）"""
    global _jwe_key
    if _jwe_key is None:
        if not settings.JWE_KEY:
            raise ValueError(
                "JWE_KEY 环境变量未配置。"
                "请运行 python scripts/generate_keys.py 生成密钥"
            )
        _jwe_key = json.loads(settings.JWE_KEY)
    return _jwe_key
