#!/usr/bin/env python3
"""
生成 JWK 密钥

使用方法:
  # 首次运行，创建虚拟环境
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  
  # 之后运行
  source venv/bin/activate
  python genkeys.py
"""

import secrets
import base64
import json

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码（无填充）"""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_kid() -> str:
    """生成 Key ID"""
    return b64url_encode(secrets.token_bytes(8))


def generate_ed25519_jwk_with_crypto() -> dict:
    """使用 cryptography 库生成 Ed25519 JWK"""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 获取原始字节
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kid = generate_kid()

    # 注意：Ed25519 的 d 是 32 字节的种子，x 是对应的公钥
    # 必须确保 d 和 x 匹配
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(public_bytes),
        "d": b64url_encode(private_bytes),
    }
    
    # 验证密钥对是否匹配
    print(f"  密钥验证 - 私钥种子长度: {len(private_bytes)} bytes, 公钥长度: {len(public_bytes)} bytes")
    
    return jwk


def generate_ed25519_jwk_fallback() -> dict:
    """简单生成随机 Ed25519 JWK（不使用 cryptography）"""
    # 注意：这个方法生成的不是真正的 Ed25519 密钥对
    # 仅作为 fallback，建议安装 cryptography 库
    kid = generate_kid()
    
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
        "x": b64url_encode(secrets.token_bytes(32)),  # 公钥 32 字节
        "d": b64url_encode(secrets.token_bytes(32)),  # 私钥 32 字节
    }


def generate_aes_jwk() -> dict:
    """生成 AES-256-GCM JWK"""
    key_bytes = secrets.token_bytes(32)  # AES-256
    kid = generate_kid()

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

    if not HAS_CRYPTOGRAPHY:
        print("⚠️  警告: 未安装 cryptography 库")
        print("   使用 fallback 方法生成密钥")
        print("   建议: pip3 install cryptography")
        print()

    # 生成 JWS 私钥（Ed25519）
    if HAS_CRYPTOGRAPHY:
        jws_key = generate_ed25519_jwk_with_crypto()
        print("✅ 使用 cryptography 库生成 Ed25519 密钥")
    else:
        jws_key = generate_ed25519_jwk_fallback()
        print("⚠️  使用 fallback 方法生成密钥")

    # 生成 JWE 密钥（AES-256-GCM）
    jwe_key = generate_aes_jwk()

    # JSON 序列化后 base64url 编码
    jws_key_json = json.dumps(jws_key, separators=(",", ":"))
    jwe_key_json = json.dumps(jwe_key, separators=(",", ":"))

    jws_key_b64 = b64url_encode(jws_key_json.encode("utf-8"))
    jwe_key_b64 = b64url_encode(jwe_key_json.encode("utf-8"))

    print()
    print("请将以下内容添加到 config.toml 的 [auth.token] 部分：")
    print("-" * 60)
    print()
    print(f'sign_key = "{jws_key_b64}"')
    print()
    print(f'enc_key = "{jwe_key_b64}"')
    print()
    print("-" * 60)
    print()

    # 提取公钥
    public_jwk = {
        "kty": jws_key["kty"],
        "crv": jws_key["crv"],
        "kid": jws_key["kid"],
        "use": jws_key["use"],
        "alg": jws_key["alg"],
        "x": jws_key["x"],
    }

    public_jwk_json = json.dumps(public_jwk, indent=2)
    print("签名公钥（JWKS 端点返回，可公开）：")
    print(public_jwk_json)
    print()

    print("=" * 60)
    print("✅ 密钥生成完成")
    print("=" * 60)


if __name__ == "__main__":
    main()

