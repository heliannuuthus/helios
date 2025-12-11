#!/usr/bin/env python3
"""
生成 JWK 密钥并输出到终端

使用方式：
  python scripts/generate_keys.py

将输出的内容添加到 .env 文件中
"""
import os
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_ed25519_jwk() -> dict:
    """
    生成 Ed25519 私钥（JWK 格式）
    私钥中包含公钥信息（x 字段）
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    kid = b64url_encode(os.urandom(8))

    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(public_bytes),  # 公钥部分
        "d": b64url_encode(private_bytes),  # 私钥部分
    }


def generate_aes_jwk() -> dict:
    """
    生成 AES-256-GCM 对称密钥（JWK 格式）
    """
    key_bytes = os.urandom(32)
    kid = b64url_encode(os.urandom(8))

    return {
        "kty": "oct",
        "kid": kid,
        "use": "enc",
        "alg": "A256GCM",
        "k": b64url_encode(key_bytes),
    }


def main():
    print("=" * 60)
    print("生成 JWK 密钥")
    print("=" * 60)
    print()

    # 生成 JWS 私钥（Ed25519，包含公钥信息）
    jws_key = generate_ed25519_jwk()
    
    # 生成 JWE 密钥（AES-256-GCM）
    jwe_key = generate_aes_jwk()

    # 输出环境变量格式
    print("请将以下内容添加到 .env 文件：")
    print("-" * 60)
    print()
    
    jws_key_str = json.dumps(jws_key, separators=(',', ':'))
    jwe_key_str = json.dumps(jwe_key, separators=(',', ':'))
    
    print(f"JWS_KEY='{jws_key_str}'")
    print()
    print(f"JWE_KEY='{jwe_key_str}'")
    print()
    print("-" * 60)
    print()
    
    # 提取公钥（用于 JWKS 端点）
    public_jwk = {k: v for k, v in jws_key.items() if k != "d"}
    print("JWS 公钥（JWKS 端点返回，可公开）：")
    print(json.dumps(public_jwk, indent=2))
    print()
    
    print("=" * 60)
    print("✅ 密钥生成完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
