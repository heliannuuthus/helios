#!/usr/bin/env python3
"""
Hermes 初始化脚本

功能：
1. 生成数据库加密密钥并输出 aegis.config.toml 配置片段
2. 生成域签名密钥并输出 aegis.config.toml 配置片段
3. 生成服务密钥并输出 hermes.config.toml 配置片段
4. 生成加密后的服务密钥并直接写入 sql/hermes/init.sql

密钥说明：
==========

aegis.config.toml:
  - [aegis.domains.{domain}] sign-key: Base64URL 编码的 Ed25519 JWK，用于签名 JWT Token

hermes.config.toml:
  - [db] enc-key: Base64 编码的 32 字节 AES 密钥，用于加密所有敏感数据
  - [aegis] secret-key: Base64URL 编码的 AES-256 JWK，hermes 服务的密钥（用于验证 CAT）

sql/hermes/init.sql:
  - t_service.encrypted_key: 服务密钥的密文（用 db.enc-key 加密）

使用方法:
  cd scripts
  pip install -r requirements.txt
  python initialize-hermes.py
"""

import secrets
import base64
import json
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("请安装 cryptography 库: pip install cryptography")
    exit(1)


# ==================== 路径配置 ====================

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
INIT_SQL_PATH = PROJECT_ROOT / "sql" / "hermes" / "init.sql"


# ==================== 预制数据定义 ====================

@dataclass
class Domain:
    """域定义"""
    domain_id: str
    name: str
    description: str


@dataclass
class Service:
    """服务定义"""
    service_id: str
    domain_id: str
    name: str
    description: str = ""
    access_token_expires_in: int = 7200
    refresh_token_expires_in: int = 604800


@dataclass
class Application:
    """应用定义"""
    app_id: str
    domain_id: str
    name: str
    logo_url: Optional[str] = None
    redirect_uris: list[str] = field(default_factory=list)
    allowed_idps: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)


@dataclass
class AppServiceRelation:
    """应用服务关系"""
    app_id: str
    service_id: str
    relation: str = "*"


@dataclass
class User:
    """用户定义"""
    openid: str
    domain_id: str
    email: str
    email_verified: bool = True
    nickname: Optional[str] = None
    status: int = 0


@dataclass
class Relationship:
    """权限关系"""
    service_id: str
    subject_type: str
    subject_id: str
    relation: str
    object_type: str
    object_id: str


# ==================== 预制数据 ====================

DOMAINS = [
    Domain("ciam", "Customer Identity", "C端用户身份域"),
    Domain("piam", "Partner Identity", "B端用户身份域"),
]

SERVICES = [
    # domain_id = "-" 表示跨域内置服务，属于全部域
    Service("hermes", "-", "Hermes 管理服务", "身份与访问管理服务"),
    Service("iris", "-", "Iris 用户服务", "用户信息管理服务"),
]

APPLICATIONS = [
    Application(
        app_id="atlas",
        domain_id="piam",
        name="Atlas 管理控制台",
        logo_url="https://aegis.heliannuuthus.com/logos/atlas.svg",
        redirect_uris=["https://atlas.heliannuuthus.com/auth/callback"],
        allowed_idps=["email", "google", "github"],
        allowed_origins=["https://atlas.heliannuuthus.com"],
    ),
]

APP_SERVICE_RELATIONS = [
    AppServiceRelation("atlas", "hermes", "*"),
]

USERS = [
    User(
        openid="heliannuuthus",
        domain_id="piam",
        email="heliannuuthus@gmail.com",
        email_verified=True,
        nickname="Heliannuuthus",
    ),
]

RELATIONSHIPS = [
    Relationship("hermes", "user", "heliannuuthus", "admin", "*", "*"),
]


# ==================== 密钥工具函数 ====================

def b64_encode(data: bytes) -> str:
    """标准 Base64 编码"""
    return base64.b64encode(data).decode("utf-8")


def b64url_encode(data: bytes) -> str:
    """Base64URL 编码（无填充）"""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def jwk_to_b64url(jwk: dict) -> str:
    """JWK 转 Base64URL 编码的 JSON"""
    return b64url_encode(json.dumps(jwk, separators=(",", ":")).encode("utf-8"))


def generate_ed25519_jwk(kid: str) -> dict:
    """生成 Ed25519 签名密钥 JWK"""
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": kid,
        "d": b64url_encode(private_bytes),
        "x": b64url_encode(public_bytes),
    }


def generate_aes256_jwk(kid: str) -> tuple[dict, bytes]:
    """生成 AES-256 加密密钥 JWK，返回 (JWK, 原始密钥)"""
    key_bytes = secrets.token_bytes(32)
    jwk = {
        "kty": "oct",
        "kid": kid,
        "k": b64url_encode(key_bytes),
        "alg": "A256GCM",
        "use": "enc",
    }
    return jwk, key_bytes


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: str) -> bytes:
    """AES-256-GCM 加密，返回 IV || Ciphertext || Tag"""
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad.encode("utf-8") if aad else None)
    return iv + ciphertext


# ==================== 生成器 ====================

@dataclass
class ServiceData:
    """服务数据"""
    service: Service
    secret_jwk: dict
    encrypted_key: str  # Base64 密文


class Initializer:
    def __init__(self):
        self.db_enc_key: bytes = b""  # 数据库加密密钥
        self.domain_sign_keys: dict[str, dict] = {}  # 域签名密钥 JWK
        self.services_data: list[ServiceData] = []

    def generate_all(self):
        """生成所有密钥"""
        # 1. 生成数据库加密密钥
        self.db_enc_key = secrets.token_bytes(32)

        # 2. 生成域签名密钥
        for domain in DOMAINS:
            self.domain_sign_keys[domain.domain_id] = generate_ed25519_jwk(f"{domain.domain_id}-sign")

        # 3. 生成服务密钥并加密
        for service in SERVICES:
            # 生成服务密钥
            secret_jwk, secret_key_raw = generate_aes256_jwk(f"{service.service_id}-secret")
            
            # 用数据库加密密钥加密服务密钥
            encrypted = encrypt_aes_gcm(self.db_enc_key, secret_key_raw, service.service_id)
            
            self.services_data.append(ServiceData(
                service=service,
                secret_jwk=secret_jwk,
                encrypted_key=b64_encode(encrypted),
            ))

    def output_aegis_config(self) -> str:
        """生成 aegis.config.toml 配置片段"""
        lines = []
        # 域签名密钥
        for domain in DOMAINS:
            sign_jwk = self.domain_sign_keys.get(domain.domain_id)
            if not sign_jwk:
                continue
            lines.append(f"[aegis.domains.{domain.domain_id}]")
            lines.append(f'name = "{domain.name}"')
            lines.append(f'description = "{domain.description}"')
            lines.append(f'sign-key = "{jwk_to_b64url(sign_jwk)}"')
            lines.append("")
        return "\n".join(lines)

    def output_hermes_config(self) -> str:
        """生成 hermes.config.toml 配置片段"""
        lines = []
        # 数据库加密密钥
        lines.append("[db]")
        lines.append(f'enc-key = "{b64_encode(self.db_enc_key)}"  # 数据库加密密钥（用于加密敏感数据）')
        lines.append("")
        
        # 服务密钥
        for sd in self.services_data:
            lines.append(f"# {sd.service.name} ({sd.service.service_id})")
            lines.append("[aegis]")
            lines.append(f'secret-key = "{jwk_to_b64url(sd.secret_jwk)}"')
            lines.append("")
        return "\n".join(lines)

    def generate_init_sql(self) -> str:
        """生成 init.sql 内容"""
        lines = []
        lines.append("-- Hermes 初始化数据")
        lines.append("-- 由 scripts/initialize-hermes.py 生成")
        lines.append("")
        lines.append("USE `hermes`;")
        lines.append("")

        # Services
        lines.append("-- ==================== 服务 ====================")
        lines.append("-- domain_id = '-' 表示跨域内置服务，属于全部域")
        lines.append("INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES")
        service_values = []
        for sd in self.services_data:
            svc = sd.service
            desc = svc.description.replace("'", "''")
            service_values.append(f"('{svc.service_id}', '{svc.domain_id}', '{svc.name}', '{desc}', '{sd.encrypted_key}', {svc.access_token_expires_in}, {svc.refresh_token_expires_in})")
        lines.append(",\n".join(service_values))
        lines.append("ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);")
        lines.append("")

        # Applications
        if APPLICATIONS:
            lines.append("-- ==================== 应用 ====================")
            lines.append("INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_idps, allowed_origins) VALUES")
            app_values = []
            for app in APPLICATIONS:
                logo_url = f"'{app.logo_url}'" if app.logo_url else "NULL"
                redirect_uris = f"'{json.dumps(app.redirect_uris)}'" if app.redirect_uris else "NULL"
                allowed_idps = f"'{json.dumps(app.allowed_idps)}'" if app.allowed_idps else "NULL"
                allowed_origins = f"'{json.dumps(app.allowed_origins)}'" if app.allowed_origins else "NULL"
                app_values.append(f"('{app.app_id}', '{app.domain_id}', '{app.name}', {logo_url}, {redirect_uris}, {allowed_idps}, {allowed_origins})")
            lines.append(",\n".join(app_values))
            lines.append("ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_idps = VALUES(allowed_idps), allowed_origins = VALUES(allowed_origins);")
            lines.append("")

        # App Service Relations
        if APP_SERVICE_RELATIONS:
            lines.append("-- ==================== 应用服务关系 ====================")
            lines.append("INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES")
            rel_values = []
            for rel in APP_SERVICE_RELATIONS:
                rel_values.append(f"('{rel.app_id}', '{rel.service_id}', '{rel.relation}')")
            lines.append(",\n".join(rel_values))
            lines.append("ON DUPLICATE KEY UPDATE relation = VALUES(relation);")
            lines.append("")

        # Users
        if USERS:
            lines.append("-- ==================== 用户 ====================")
            lines.append("INSERT INTO t_user (openid, domain_id, status, email_verified, nickname, picture, email) VALUES")
            user_values = []
            for user in USERS:
                nickname = f"'{user.nickname}'" if user.nickname else "NULL"
                email_verified = 1 if user.email_verified else 0
                user_values.append(f"('{user.openid}', '{user.domain_id}', {user.status}, {email_verified}, {nickname}, NULL, '{user.email}')")
            lines.append(",\n".join(user_values))
            lines.append("ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified);")
            lines.append("")

        # Relationships
        if RELATIONSHIPS:
            lines.append("-- ==================== 服务关系（权限） ====================")
            lines.append("INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES")
            rel_values = []
            for rel in RELATIONSHIPS:
                rel_values.append(f"('{rel.service_id}', '{rel.subject_type}', '{rel.subject_id}', '{rel.relation}', '{rel.object_type}', '{rel.object_id}')")
            lines.append(",\n".join(rel_values))
            lines.append("ON DUPLICATE KEY UPDATE relation = VALUES(relation);")
        
        return "\n".join(lines)

    def run(self):
        """运行初始化"""
        print("=" * 60)
        print("Hermes 初始化脚本")
        print("=" * 60)
        print()

        # 生成密钥
        print("正在生成密钥...")
        self.generate_all()
        print("  ✅ 数据库加密密钥已生成")
        print("  ✅ 域签名密钥已生成")
        print("  ✅ 服务密钥已生成并加密")
        print()

        # 输出 aegis.config.toml 配置
        print("=" * 60)
        print("aegis.config.toml - 复制以下内容替换配置")
        print("=" * 60)
        print()
        print(self.output_aegis_config())

        # 输出 hermes.config.toml 配置
        print("=" * 60)
        print("hermes.config.toml - 复制以下内容替换 [aegis] 配置")
        print("=" * 60)
        print()
        print(self.output_hermes_config())

        # 写入 init.sql
        init_sql = self.generate_init_sql()
        INIT_SQL_PATH.write_text(init_sql, encoding="utf-8")
        print("=" * 60)
        print(f"✅ 已写入: {INIT_SQL_PATH}")
        print("=" * 60)


def main():
    initializer = Initializer()
    initializer.run()


if __name__ == "__main__":
    main()
