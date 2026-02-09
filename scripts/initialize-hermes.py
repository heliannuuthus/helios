#!/usr/bin/env python3
"""
Hermes 初始化脚本

功能：
1. 生成数据库加密密钥并输出配置片段
2. 生成域签名密钥（32 字节 Ed25519 seed）并输出配置片段
3. 生成服务密钥（32 字节）并输出配置片段
4. 生成加密后的服务密钥并直接写入 sql/hermes/init.sql

密钥说明：
==========

所有密钥统一使用 32 字节原始格式，Base64URL 编码（无填充）

aegis.config.toml:
  - [aegis.domains.{domain}] sign-keys: Base64URL 编码的 32 字节 Ed25519 seed
    支持密钥轮换，逗号分隔多个密钥，第一把是主密钥

hermes.config.toml:
  - [db] enc-key: Base64 编码的 32 字节 AES-256 密钥，用于加密敏感数据
  - [aegis] secret-key: Base64URL 编码的 32 字节密钥，服务的对称加密密钥

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
    allowed_origins: list[str] = field(default_factory=list)


@dataclass
class AppIdpConfig:
    """应用 IDP 配置"""
    app_id: str
    idp_type: str  # IDP 类型：email/google/github/wechat:mp 等
    priority: int = 0  # 排序优先级（值越大越靠前）
    strategy: Optional[str] = None  # 登录策略（仅 user/oper）：password,email_otp,webauthn
    delegate: Optional[str] = None  # 委托 MFA：email_otp,totp,webauthn
    require: Optional[str] = None  # 前置验证：captcha


@dataclass
class AppServiceRelation:
    """应用服务关系"""
    app_id: str
    service_id: str
    relation: str = "*"


@dataclass
class User:
    """用户定义"""
    uid: str
    email: str
    email_verified: bool = True
    nickname: Optional[str] = None
    status: int = 0


@dataclass
class UserIdentity:
    """用户身份定义"""
    domain: str       # 身份所属域：ciam/piam
    uid: str          # 内部 uid（关联 t_user.uid）
    idp: str          # IDP 类型：global/user/oper
    t_openid: str     # 对外标识（global 为域级 sub，其他为 IDP 返回的 openid）


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
        allowed_origins=["https://atlas.heliannuuthus.com"],
    ),
]

APP_IDP_CONFIGS = [
    # Atlas 应用的 IDP 配置
    AppIdpConfig("atlas", "oper", priority=10, strategy="password",delegate="email_otp,webauthn", require="captcha"),
    AppIdpConfig("atlas", "google", priority=5),
    AppIdpConfig("atlas", "github", priority=5),
]

APP_SERVICE_RELATIONS = [
    AppServiceRelation("atlas", "hermes", "*"),
]

USERS = [
    User(
        uid="heliannuuthus",
        email="heliannuuthus@gmail.com",
        email_verified=True,
        nickname="Heliannuuthus",
    ),
]

# 用户身份（global 身份为域级对外标识，user/oper 为认证身份）
USER_IDENTITIES = [
    UserIdentity(domain="piam", uid="heliannuuthus", idp="global", t_openid=secrets.token_hex(16)),
    UserIdentity(domain="piam", uid="heliannuuthus", idp="oper", t_openid="heliannuuthus"),
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


def generate_32byte_key() -> bytes:
    """生成 32 字节随机密钥"""
    return secrets.token_bytes(32)


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
    secret_key: bytes      # 32 字节原始密钥
    encrypted_key: str     # Base64 密文


class Initializer:
    def __init__(self):
        self.db_enc_key: bytes = b""  # 数据库加密密钥（32 字节）
        self.domain_sign_keys: dict[str, bytes] = {}  # 域签名密钥（32 字节 Ed25519 seed）
        self.services_data: list[ServiceData] = []

    def generate_all(self):
        """生成所有密钥"""
        # 1. 生成数据库加密密钥（32 字节）
        self.db_enc_key = generate_32byte_key()

        # 2. 生成域签名密钥（32 字节 Ed25519 seed）
        for domain in DOMAINS:
            self.domain_sign_keys[domain.domain_id] = generate_32byte_key()

        # 3. 生成服务密钥并加密
        for service in SERVICES:
            # 生成服务密钥（32 字节）
            secret_key = generate_32byte_key()
            
            # 用数据库加密密钥加密服务密钥
            encrypted = encrypt_aes_gcm(self.db_enc_key, secret_key, service.service_id)
            
            self.services_data.append(ServiceData(
                service=service,
                secret_key=secret_key,
                encrypted_key=b64_encode(encrypted),
            ))

    def output_hermes_config(self) -> str:
        """生成 hermes.toml 配置片段（含域签名密钥和 hermes 服务密钥）"""
        lines = []
        
        # 数据库加密密钥
        lines.append("[db]")
        lines.append("# 数据库加密密钥（32 字节 AES-256，Base64 编码）")
        lines.append("enc-key = '''")
        lines.append(b64_encode(self.db_enc_key))
        lines.append("'''")
        lines.append("")
        
        # 域签名密钥（放在 hermes.toml）
        for domain in DOMAINS:
            sign_key = self.domain_sign_keys.get(domain.domain_id)
            if not sign_key:
                continue
            lines.append(f"[aegis.domains.{domain.domain_id}]")
            lines.append(f'name = "{domain.name}"')
            lines.append(f'description = "{domain.description}"')
            lines.append("# 签名密钥（32 字节 Ed25519 seed，Base64URL 编码）")
            lines.append("# 支持密钥轮换：逗号分隔多个密钥，第一把是主密钥")
            lines.append("sign-keys = '''")
            lines.append(b64url_encode(sign_key))
            lines.append("'''")
            lines.append("")
        
        # Hermes 服务密钥
        hermes_data = next((sd for sd in self.services_data if sd.service.service_id == "hermes"), None)
        if hermes_data:
            lines.append("[aegis]")
            lines.append("# Hermes 服务密钥（32 字节，Base64URL 编码）")
            lines.append("secret-key = '''")
            lines.append(b64url_encode(hermes_data.secret_key))
            lines.append("'''")
            lines.append("")
        
        return "\n".join(lines)

    def output_iris_config(self) -> str:
        """生成 iris.toml 配置片段"""
        lines = []
        
        # Iris 服务密钥
        iris_data = next((sd for sd in self.services_data if sd.service.service_id == "iris"), None)
        if iris_data:
            lines.append("[aegis]")
            lines.append("# Iris 服务的 audience（用于 token 验证）")
            lines.append('audience = "iris"')
            lines.append("")
            lines.append("# Iris 服务密钥（32 字节，Base64URL 编码）")
            lines.append("secret-key = '''")
            lines.append(b64url_encode(iris_data.secret_key))
            lines.append("'''")
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
            lines.append("INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_origins) VALUES")
            app_values = []
            for app in APPLICATIONS:
                logo_url = f"'{app.logo_url}'" if app.logo_url else "NULL"
                redirect_uris = f"'{json.dumps(app.redirect_uris)}'" if app.redirect_uris else "NULL"
                allowed_origins = f"'{json.dumps(app.allowed_origins)}'" if app.allowed_origins else "NULL"
                app_values.append(f"('{app.app_id}', '{app.domain_id}', '{app.name}', {logo_url}, {redirect_uris}, {allowed_origins})")
            lines.append(",\n".join(app_values))
            lines.append("ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins);")
            lines.append("")

        # Application IDP Configs
        if APP_IDP_CONFIGS:
            lines.append("-- ==================== 应用 IDP 配置 ====================")
            lines.append("INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES")
            idp_values = []
            for cfg in APP_IDP_CONFIGS:
                strategy = f"'{cfg.strategy}'" if cfg.strategy else "NULL"
                delegate = f"'{cfg.delegate}'" if cfg.delegate else "NULL"
                require = f"'{cfg.require}'" if cfg.require else "NULL"
                idp_values.append(f"('{cfg.app_id}', '{cfg.idp_type}', {cfg.priority}, {strategy}, {delegate}, {require})")
            lines.append(",\n".join(idp_values))
            lines.append("ON DUPLICATE KEY UPDATE priority = VALUES(priority), strategy = VALUES(strategy), delegate = VALUES(delegate), `require` = VALUES(`require`);")
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
            lines.append("INSERT INTO t_user (uid, status, email_verified, nickname, picture, email) VALUES")
            user_values = []
            for user in USERS:
                nickname = f"'{user.nickname}'" if user.nickname else "NULL"
                email_verified = 1 if user.email_verified else 0
                user_values.append(f"('{user.uid}', {user.status}, {email_verified}, {nickname}, NULL, '{user.email}')")
            lines.append(",\n".join(user_values))
            lines.append("ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified);")
            lines.append("")

        # User Identities
        if USER_IDENTITIES:
            lines.append("-- ==================== 用户身份 ====================")
            lines.append("-- global 身份为域级对外标识（token 中的 sub），其他为认证身份")
            lines.append("INSERT INTO t_user_identity (domain, uid, idp, t_openid) VALUES")
            identity_values = []
            for identity in USER_IDENTITIES:
                identity_values.append(f"('{identity.domain}', '{identity.uid}', '{identity.idp}', '{identity.t_openid}')")
            lines.append(",\n".join(identity_values))
            lines.append("ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);")
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

        # 输出 hermes.toml 配置
        print("=" * 60)
        print("hermes.toml - 复制以下内容到配置文件")
        print("=" * 60)
        print()
        print(self.output_hermes_config())

        # 输出 iris.toml 配置
        print("=" * 60)
        print("iris.toml - 复制以下内容到配置文件")
        print("=" * 60)
        print()
        print(self.output_iris_config())

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
