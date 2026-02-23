#!/usr/bin/env python3
"""
Hermes 初始化脚本

功能：
1. 生成数据库加密密钥，直接写入 hermes.toml
2. 生成域签名密钥（32 字节 Ed25519 seed），直接写入 hermes.toml
3. 生成 SSO master key（32 字节），直接写入 aegis.toml
4. 生成服务密钥（32 字节），直接写入 hermes.toml / iris.toml
5. 生成加密后的服务密钥，直接写入 sql/hermes/init.sql
6. 生成初始用户密码（随机），写入 init.sql

密钥说明：
==========

所有密钥统一使用 32 字节原始格式，Base64URL 编码（无填充）

aegis.toml:
  - [sso] master-key: Base64URL 编码的 32 字节密钥
    通过 KDF 派生 Ed25519 签名密钥和 AES-256 加密密钥

hermes.toml:
  - [db] enc-key: Base64 编码的 32 字节 AES-256 密钥，用于加密敏感数据
  - [aegis.domains.{domain}] sign-keys: Base64URL 编码的 32 字节 Ed25519 seed
    支持密钥轮换，逗号分隔多个密钥，第一把是主密钥
  - [aegis] secret-key: Base64URL 编码的 32 字节密钥，服务的对称加密密钥

iris.toml:
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
import string
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("请安装 cryptography 库: pip install cryptography")
    exit(1)

try:
    import bcrypt as _bcrypt
except ImportError:
    print("请安装 bcrypt 库: pip install bcrypt")
    exit(1)

try:
    import tomlkit
except ImportError:
    print("请安装 tomlkit 库: pip install tomlkit")
    exit(1)


# ==================== 路径配置 ====================

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "config"
INIT_SQL_PATH = PROJECT_ROOT / "sql" / "hermes" / "init.sql"

HERMES_TOML = CONFIG_DIR / "hermes.toml"
AEGIS_TOML = CONFIG_DIR / "aegis.toml"
IRIS_TOML = CONFIG_DIR / "iris.toml"


# ==================== 预制数据定义 ====================

@dataclass
class Domain:
    domain_id: str
    name: str
    description: str


@dataclass
class Service:
    service_id: str
    domain_id: str
    name: str
    description: str = ""
    access_token_expires_in: int = 7200
    refresh_token_expires_in: int = 604800


@dataclass
class Application:
    app_id: str
    domain_id: str
    name: str
    logo_url: Optional[str] = None
    redirect_uris: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)


@dataclass
class AppIdpConfig:
    app_id: str
    idp_type: str
    priority: int = 0
    strategy: Optional[str] = None
    delegate: Optional[str] = None
    require: Optional[str] = None


@dataclass
class AppServiceRelation:
    app_id: str
    service_id: str
    relation: str = "*"


@dataclass
class User:
    openid: str
    email: str
    username: Optional[str] = None
    password: Optional[str] = None
    email_verified: bool = True
    nickname: Optional[str] = None
    status: int = 0


@dataclass
class UserIdentity:
    domain: str
    openid: str
    idp: str
    t_openid: str


@dataclass
class Relationship:
    service_id: str
    subject_type: str
    subject_id: str
    relation: str
    object_type: str
    object_id: str


# ==================== 工具函数 ====================

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_32byte_key() -> bytes:
    return secrets.token_bytes(32)


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%^&*" for c in password)):
            return password


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt(rounds=10)).decode("utf-8")


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: str) -> bytes:
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad.encode("utf-8") if aad else None)
    return iv + ciphertext


def load_toml(path: Path) -> tomlkit.TOMLDocument:
    if path.exists():
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    return tomlkit.document()


def save_toml(path: Path, doc: tomlkit.TOMLDocument):
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def ensure_table(doc, *keys: str):
    current = doc
    for key in keys:
        if key not in current:
            current[key] = tomlkit.table()
        current = current[key]
    return current


# ==================== 预制数据 ====================

DOMAINS = [
    Domain("consumer", "Consumer Identity", "C端用户身份域"),
    Domain("platform", "Platform Identity", "B端平台身份域"),
]

SERVICES = [
    Service("hermes", "-", "Hermes 管理服务", "身份与访问管理服务"),
    Service("iris", "-", "Iris 用户服务", "用户信息管理服务"),
]

APPLICATIONS = [
    Application(
        app_id="atlas",
        domain_id="platform",
        name="Atlas 管理控制台",
        logo_url="https://aegis.heliannuuthus.com/logos/atlas.svg",
        redirect_uris=["https://atlas.heliannuuthus.com/auth/callback"],
        allowed_origins=["https://atlas.heliannuuthus.com"],
    ),
    Application(
        app_id="piris",
        domain_id="platform",
        name="平台个人中心",
        redirect_uris=["https://iris.heliannuuthus.com/auth/callback"],
        allowed_origins=["https://iris.heliannuuthus.com"],
    ),
    Application(
        app_id="ciris",
        domain_id="consumer",
        name="用户个人中心",
        redirect_uris=["https://iris.heliannuuthus.com/auth/callback"],
        allowed_origins=["https://iris.heliannuuthus.com"],
    ),
]

APP_IDP_CONFIGS = [
    AppIdpConfig("atlas", "staff", priority=10, strategy="password", delegate="email_otp,webauthn", require="captcha"),
    AppIdpConfig("atlas", "google", priority=5),
    AppIdpConfig("atlas", "github", priority=5),
    AppIdpConfig("piris", "staff", priority=10, strategy="password", delegate="email_otp,webauthn", require="captcha"),
    AppIdpConfig("piris", "google", priority=5),
    AppIdpConfig("piris", "github", priority=5),
    AppIdpConfig("ciris", "user", priority=10, strategy="password", delegate="sms_otp"),
    AppIdpConfig("ciris", "wechat-mp", priority=5),
    AppIdpConfig("ciris", "wechat-web", priority=5),
]

APP_SERVICE_RELATIONS = [
    AppServiceRelation("atlas", "hermes", "*"),
    AppServiceRelation("piris", "iris", "*"),
    AppServiceRelation("ciris", "iris", "*"),
]

USERS = [
    User(
        openid="heliannuuthus",
        email="heliannuuthus@gmail.com",
        username="heliannuuthus",
        password=generate_password(),
        email_verified=True,
        nickname="Heliannuuthus",
    ),
]

USER_IDENTITIES = [
    UserIdentity(domain="platform", openid="heliannuuthus", idp="global", t_openid=secrets.token_hex(16)),
    UserIdentity(domain="platform", openid="heliannuuthus", idp="staff", t_openid="heliannuuthus"),
]

RELATIONSHIPS = [
    Relationship("hermes", "user", "heliannuuthus", "admin", "*", "*"),
]


# ==================== 生成器 ====================

@dataclass
class ServiceData:
    service: Service
    secret_key: bytes
    encrypted_key: str


class Initializer:
    def __init__(self):
        self.db_enc_key: bytes = b""
        self.domain_sign_keys: dict[str, bytes] = {}
        self.sso_master_key: bytes = b""
        self.services_data: list[ServiceData] = []

    def generate_all(self):
        self.db_enc_key = generate_32byte_key()

        for domain in DOMAINS:
            self.domain_sign_keys[domain.domain_id] = generate_32byte_key()

        self.sso_master_key = generate_32byte_key()

        for service in SERVICES:
            secret_key = generate_32byte_key()
            encrypted = encrypt_aes_gcm(self.db_enc_key, secret_key, service.service_id)
            self.services_data.append(ServiceData(
                service=service,
                secret_key=secret_key,
                encrypted_key=b64_encode(encrypted),
            ))

    def update_hermes_toml(self):
        doc = load_toml(HERMES_TOML)

        ensure_table(doc, "db")["enc-key"] = b64_encode(self.db_enc_key)

        for domain in DOMAINS:
            sign_key = self.domain_sign_keys.get(domain.domain_id)
            if not sign_key:
                continue
            dt = ensure_table(doc, "aegis", "domains", domain.domain_id)
            dt["name"] = domain.name
            dt["description"] = domain.description
            dt["sign-keys"] = b64url_encode(sign_key)

        hermes_data = next((sd for sd in self.services_data if sd.service.service_id == "hermes"), None)
        if hermes_data:
            ensure_table(doc, "aegis")["secret-key"] = b64url_encode(hermes_data.secret_key)

        save_toml(HERMES_TOML, doc)

    def update_aegis_toml(self):
        doc = load_toml(AEGIS_TOML)

        if "sso" not in doc:
            doc.add(tomlkit.nl())
            doc.add("sso", tomlkit.table())
        doc["sso"]["master-key"] = b64url_encode(self.sso_master_key)

        save_toml(AEGIS_TOML, doc)

    def update_iris_toml(self):
        doc = load_toml(IRIS_TOML)

        iris_data = next((sd for sd in self.services_data if sd.service.service_id == "iris"), None)
        if iris_data:
            aegis = ensure_table(doc, "aegis")
            aegis["audience"] = "iris"
            aegis["secret-key"] = b64url_encode(iris_data.secret_key)

        save_toml(IRIS_TOML, doc)

    def generate_init_sql(self) -> str:
        lines = []
        lines.append("-- Hermes 初始化数据")
        lines.append("-- 由 scripts/initialize-hermes.py 生成")
        lines.append("")
        lines.append("USE `hermes`;")
        lines.append("")

        lines.append("-- ==================== 服务 ====================")
        lines.append("INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES")
        service_values = []
        for sd in self.services_data:
            svc = sd.service
            desc = svc.description.replace("'", "''")
            service_values.append(f"('{svc.service_id}', '{svc.domain_id}', '{svc.name}', '{desc}', '{sd.encrypted_key}', {svc.access_token_expires_in}, {svc.refresh_token_expires_in})")
        lines.append(",\n".join(service_values))
        lines.append("ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);")
        lines.append("")

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

        if APP_SERVICE_RELATIONS:
            lines.append("-- ==================== 应用服务关系 ====================")
            lines.append("INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES")
            rel_values = []
            for rel in APP_SERVICE_RELATIONS:
                rel_values.append(f"('{rel.app_id}', '{rel.service_id}', '{rel.relation}')")
            lines.append(",\n".join(rel_values))
            lines.append("ON DUPLICATE KEY UPDATE relation = VALUES(relation);")
            lines.append("")

        if USERS:
            lines.append("-- ==================== 用户 ====================")
            lines.append("INSERT INTO t_user (openid, status, username, password_hash, email_verified, nickname, picture, email) VALUES")
            user_values = []
            for user in USERS:
                nickname = f"'{user.nickname}'" if user.nickname else "NULL"
                username = f"'{user.username}'" if user.username else "NULL"
                password_hash = f"'{hash_password(user.password)}'" if user.password else "NULL"
                email_verified = 1 if user.email_verified else 0
                user_values.append(f"('{user.openid}', {user.status}, {username}, {password_hash}, {email_verified}, {nickname}, NULL, '{user.email}')")
            lines.append(",\n".join(user_values))
            lines.append("ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);")
            lines.append("")

        if USER_IDENTITIES:
            lines.append("-- ==================== 用户身份 ====================")
            lines.append("INSERT INTO t_user_identity (domain, openid, idp, t_openid) VALUES")
            identity_values = []
            for identity in USER_IDENTITIES:
                identity_values.append(f"('{identity.domain}', '{identity.openid}', '{identity.idp}', '{identity.t_openid}')")
            lines.append(",\n".join(identity_values))
            lines.append("ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);")
            lines.append("")

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
        print("=" * 60)
        print("Hermes 初始化脚本")
        print("=" * 60)
        print()

        print("正在生成密钥...")
        self.generate_all()
        print("  ✅ 数据库加密密钥已生成")
        print("  ✅ 域签名密钥已生成")
        print("  ✅ SSO master key 已生成")
        print("  ✅ 服务密钥已生成并加密")
        print()

        print("正在写入配置文件...")

        self.update_hermes_toml()
        print(f"  ✅ 已写入: {HERMES_TOML}")

        self.update_aegis_toml()
        print(f"  ✅ 已写入: {AEGIS_TOML}")

        self.update_iris_toml()
        print(f"  ✅ 已写入: {IRIS_TOML}")

        init_sql = self.generate_init_sql()
        INIT_SQL_PATH.write_text(init_sql, encoding="utf-8")
        print(f"  ✅ 已写入: {INIT_SQL_PATH}")
        print()

        if USERS:
            print("=" * 60)
            print("初始用户凭证（请妥善保管，仅显示一次）")
            print("=" * 60)
            for user in USERS:
                print(f"  用户名: {user.username or user.email}")
                if user.password:
                    print(f"  密码:   {user.password}")
                else:
                    print("  密码:   （未设置）")
            print()

        print("=" * 60)
        print("✅ 初始化完成")
        print("=" * 60)


def main():
    initializer = Initializer()
    initializer.run()


if __name__ == "__main__":
    main()
