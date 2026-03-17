-- Hermes 数据库 Schema（身份与访问管理数据）
-- MySQL 8.0+ 语法
-- 注意：session、authorization_code、refresh_token 都存储在 Redis 中
-- 注意：域签名密钥仍从配置文件或密钥服务读取，不存库
-- 注意：IDP 的凭证（app_id/secret）存储在 t_domain_idp_credential 和 t_application_idp_config 中

-- ==================== 数据库初始化 ====================

CREATE DATABASE IF NOT EXISTS `hermes` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON `hermes`.* TO 'helios' @'%';

FLUSH PRIVILEGES;

USE `hermes`;

-- ============================================================================
-- 一、平台配置层（Domain > Application > Service）
-- ============================================================================

-- ==================== 域表 ====================
-- 域元数据及该域允许的 IDP 列表（签名密钥从配置/密钥服务读取）

CREATE TABLE IF NOT EXISTS t_domain (
    domain_id     VARCHAR(32)   NOT NULL COMMENT '域标识：consumer/platform 等',
    name          VARCHAR(128)  NOT NULL COMMENT '域名称',
    description   VARCHAR(512)  DEFAULT NULL COMMENT '域描述',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域（元数据）';

-- ==================== 域允许的 IDP 表 ====================
-- 每个域下允许使用的 IDP 类型，应用添加 IDP 时只能从此列表选

CREATE TABLE IF NOT EXISTS t_domain_idp (
    domain_id     VARCHAR(32)   NOT NULL COMMENT '域 ID',
    idp_type      VARCHAR(32)   NOT NULL COMMENT 'IDP 类型：github/google/user/staff/wxmp 等',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (domain_id, idp_type),
    CONSTRAINT fk_domain_idp_domain FOREIGN KEY (domain_id) REFERENCES t_domain(domain_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域允许的 IDP';

-- ==================== 应用表 ====================
-- OAuth2 客户端应用，属于某个 Domain

CREATE TABLE IF NOT EXISTS t_application (
    _id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain_id          VARCHAR(32)   NOT NULL COMMENT '所属域：consumer/platform',
    app_id             VARCHAR(64)   NOT NULL COMMENT '应用唯一标识',
    name               VARCHAR(128)  NOT NULL COMMENT '应用名称',
    description        VARCHAR(512)  DEFAULT NULL COMMENT '应用描述',
    logo_url           VARCHAR(512)  DEFAULT NULL COMMENT '应用 Logo URL',
    redirect_uris                   VARCHAR(2048) DEFAULT NULL COMMENT '重定向 URI 列表（JSON 数组）',
    allowed_origins                 VARCHAR(1024) DEFAULT NULL COMMENT '允许的跨域源（JSON 数组）',
    allowed_logout_uris             VARCHAR(1024) DEFAULT NULL COMMENT '登出后允许跳转的 URI（JSON 数组）',
    id_token_expires_in             INT UNSIGNED  NOT NULL DEFAULT 3600   COMMENT 'ID Token 有效期（秒）',
    refresh_token_expires_in        INT UNSIGNED  NOT NULL DEFAULT 604800 COMMENT 'Refresh Token 沉寂有效期（秒）',
    refresh_token_absolute_expires_in INT UNSIGNED NOT NULL DEFAULT 0    COMMENT 'Refresh Token 绝对有效期（秒），0=不限制',
    -- 时间戳
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE app_id = ?
UNIQUE KEY uk_app_id (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth2 应用';

-- ==================== IDP 密钥表 ====================
-- 全局存储第三方 IDP 凭证，(idp_type, t_app_id) 唯一

CREATE TABLE IF NOT EXISTS t_idp_key (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    idp_type     VARCHAR(32)   NOT NULL COMMENT 'IDP 类型：github/google/wxmp/ttmp 等',
    t_app_id     VARCHAR(256)  NOT NULL COMMENT '第三方 IDP 的 App ID / Client ID',
    t_secret     VARCHAR(2048) NOT NULL COMMENT '加密 JSON（AES-GCM），含 secret/private_key 等',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

UNIQUE KEY uk_idp_app (idp_type, t_app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='IDP 密钥';

-- ==================== 域 IDP 配置表 ====================
-- 域级别的 IDP 默认配置，引用 t_idp_key 中的 t_app_id

CREATE TABLE IF NOT EXISTS t_domain_idp_config (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain_id    VARCHAR(32)   NOT NULL COMMENT '域 ID',
    idp_type     VARCHAR(32)   NOT NULL COMMENT 'IDP 类型：github/google/wxmp/ttmp 等',
    priority     INT           NOT NULL DEFAULT 0 COMMENT '排序优先级（值越大越靠前）',
    strategy     VARCHAR(256)  DEFAULT NULL COMMENT '认证方式：password,webauthn',
    t_app_id     VARCHAR(256)  NOT NULL COMMENT '引用 t_idp_key 的 t_app_id',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

UNIQUE KEY uk_domain_idp_type (domain_id, idp_type),
    INDEX idx_domain_priority (domain_id, priority DESC),
    CONSTRAINT fk_idp_cfg_domain FOREIGN KEY (domain_id) REFERENCES t_domain(domain_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域 IDP 配置';

-- ==================== 应用 IDP 配置表 ====================
-- 应用级别的 IDP 配置，可选覆盖 t_app_id（NULL=使用域默认）

CREATE TABLE IF NOT EXISTS t_application_idp_config (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    app_id       VARCHAR(64)   NOT NULL COMMENT '应用 ID',
    `type`       VARCHAR(32)   NOT NULL COMMENT 'IDP 类型：github/google/wxmp/user/staff',
    priority     INT           NOT NULL DEFAULT 0 COMMENT '排序优先级（值越大越靠前）',
    strategy     VARCHAR(256)  DEFAULT NULL COMMENT '认证方式（仅 user/staff）：password,webauthn',
    t_app_id     VARCHAR(256)  DEFAULT NULL COMMENT '引用 t_idp_key 的 t_app_id（NULL=使用域默认）',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

UNIQUE KEY uk_app_type (app_id, `type`),
    INDEX idx_app_priority (app_id, priority DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='应用 IDP 配置';

-- ==================== 服务表 ====================
-- 业务服务定义，每个服务有独立的密钥和 Token 配置

CREATE TABLE IF NOT EXISTS t_service (
    _id                       INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain_id                 VARCHAR(32)   NOT NULL COMMENT '所属域：consumer/platform；- 表示跨域（底层约定，不在 API 暴露）',
    service_id                VARCHAR(32)   NOT NULL COMMENT '服务标识：hermes/zwei/order',
    name                      VARCHAR(128)  NOT NULL COMMENT '服务名称',
    description               VARCHAR(512)  DEFAULT NULL COMMENT '服务描述',
    logo_url                  VARCHAR(512)  DEFAULT NULL COMMENT '服务 Logo URL',
    access_token_expires_in   INT UNSIGNED  NOT NULL DEFAULT 7200 COMMENT 'Access Token 有效期（秒），由服务控制',
    required_identities       VARCHAR(512)  DEFAULT NULL COMMENT '访问需要的身份类型（JSON 数组）',
    -- 时间戳
    created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE service_id = ?
UNIQUE KEY uk_service_id (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='业务服务';

-- ==================== 密钥表 ====================
-- Application / Service 的签名密钥，支持多密钥轮换

CREATE TABLE IF NOT EXISTS t_key (
    _id            INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    owner_type     VARCHAR(16)   NOT NULL COMMENT '所属类型：application / service',
    owner_id       VARCHAR(64)   NOT NULL COMMENT '所属 ID：app_id / service_id',
    encrypted_key  VARCHAR(256)  NOT NULL COMMENT '加密密钥（AES-GCM 加密的 48B seed，Base64 编码）',
    expired_at     DATETIME      DEFAULT NULL COMMENT '过期时间，NULL=当前主密钥',
    -- 时间戳
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

-- 索引：按 owner 查询有效密钥，最新的在前
INDEX idx_owner (owner_type, owner_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='签名密钥';

-- ==================== 服务 Challenge 配置表 ====================
-- 服务级别的 Challenge 配置（限流等），覆盖全局默认

CREATE TABLE IF NOT EXISTS t_service_challenge_setting (
    _id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    service_id   VARCHAR(32)  NOT NULL COMMENT '服务 ID',
    `type`       VARCHAR(64)  NOT NULL COMMENT 'Challenge 类型[:场景]，如 email_otp / email_otp:login',
    expires_in   INT UNSIGNED NOT NULL DEFAULT 300 COMMENT 'Challenge 有效期（秒）',
    limits       JSON         NOT NULL COMMENT '限流配置，如 {"1m": 1, "24h": 10}',
    -- 时间戳
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE service_id = ? AND type = ?
UNIQUE KEY uk_service_type (service_id, `type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='服务 Challenge 配置';

-- ==================== 应用服务关系表 ====================
-- 定义应用可以访问哪些服务的哪些关系

CREATE TABLE IF NOT EXISTS t_application_service_relation (
    _id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    app_id       VARCHAR(64)  NOT NULL COMMENT '应用 ID',
    service_id   VARCHAR(32)  NOT NULL COMMENT '服务 ID',
    relation     VARCHAR(32)  NOT NULL DEFAULT '*' COMMENT '允许的关系，* 表示全部',
    -- 时间戳
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE app_id = ? / WHERE app_id = ? AND service_id = ?
UNIQUE KEY uk_app_service_relation (app_id, service_id, relation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='应用服务关系';

-- ============================================================================
-- 二、用户层（User、Identity、Credential）
-- ============================================================================

-- ==================== 用户表 ====================
-- 用户基本信息
-- openid = 该域下 global 身份的 t_openid，即对外用户标识
-- 一个物理用户在不同域下有不同的 openid，对应不同的 t_user 记录

CREATE TABLE IF NOT EXISTS t_user (
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    openid           VARCHAR(64)   NOT NULL COMMENT '用户标识（= global identity 的 t_openid）',
    status           TINYINT       NOT NULL DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    username         VARCHAR(64)   DEFAULT NULL COMMENT '用户名（唯一）',
    password_hash    VARCHAR(256)  DEFAULT NULL COMMENT '密码哈希（bcrypt）',
    email_verified   TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '邮箱是否已验证',
    nickname         VARCHAR(128)  DEFAULT NULL COMMENT '昵称',
    picture          VARCHAR(512)  DEFAULT NULL COMMENT '头像 URL',
    email            VARCHAR(256)  DEFAULT NULL COMMENT '邮箱（明文）',
    phone            VARCHAR(64)   DEFAULT NULL COMMENT '手机号哈希（SHA256，用于查询）',
    phone_cipher     VARCHAR(256)  DEFAULT NULL COMMENT '手机号密文（AES-GCM）',
    -- 时间戳
    last_login_at    DATETIME      DEFAULT NULL COMMENT '最后登录时间',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引
-- 主查询：WHERE openid = ?
UNIQUE KEY uk_openid (openid),
    -- 登录查询：WHERE email = ? / WHERE phone = ? / WHERE username = ?
    UNIQUE KEY uk_email (email),
    UNIQUE KEY uk_phone (phone),
    UNIQUE KEY uk_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户';

-- ==================== 用户身份表 ====================
-- 用户与 IDP 的绑定关系，每个身份归属一个域（consumer/platform）
-- idp=global 的身份为该域下的对外标识（token 中的 sub）

CREATE TABLE IF NOT EXISTS t_user_identity (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain       VARCHAR(16)   NOT NULL COMMENT '身份所属域：consumer/platform',
    uid          VARCHAR(64)   NOT NULL COMMENT '用户内部标识（关联 t_user.openid）',
    idp          VARCHAR(64)   NOT NULL COMMENT 'IDP 标识：global/user/staff/github/wxmp/google 等',
    t_openid     VARCHAR(256)  NOT NULL COMMENT 'IDP 侧用户标识（global 为域级对外标识，第三方为 IDP 返回的 openid）',
    raw_data     TEXT          DEFAULT NULL COMMENT 'IDP 返回的原始数据（JSON）',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引
-- 登录查询：WHERE domain = ? AND idp = ? AND t_openid = ?
UNIQUE KEY uk_domain_idp_t_openid (domain, idp, t_openid),
    -- 查询用户绑定的身份：WHERE uid = ?
    INDEX idx_uid (uid),
    -- 查询用户在指定域的 global 身份：WHERE domain = ? AND uid = ? AND idp = 'global'
    INDEX idx_domain_uid_idp (domain, uid, idp),
    -- 外键
    CONSTRAINT fk_identity_user FOREIGN KEY (uid) REFERENCES t_user(openid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户身份';

-- ==================== 用户凭证表 ====================
-- 用户安全凭证（MFA：TOTP、WebAuthn、Passkey）

CREATE TABLE IF NOT EXISTS t_user_credential (
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    openid           VARCHAR(64)   NOT NULL COMMENT '用户标识（关联 t_user.openid）',
    `type`           VARCHAR(32)   NOT NULL COMMENT '凭证类型：totp/webauthn/passkey',
    credential_id    VARCHAR(256)  DEFAULT NULL COMMENT 'WebAuthn 凭证 ID（Base64 编码）',
    secret           VARCHAR(2048) NOT NULL COMMENT '凭证数据（AES-GCM 加密，Base64 编码的 JSON）',
    enabled          TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '是否已启用',
    -- 时间戳
    last_used_at     DATETIME      DEFAULT NULL COMMENT '最后使用时间',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引
-- WebAuthn 认证查询：WHERE credential_id = ?
UNIQUE KEY uk_credential_id (credential_id),
    -- 查询用户凭证：WHERE openid = ? AND type = ?
    INDEX idx_openid_type (openid, `type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户安全凭证（MFA）';

-- ============================================================================
-- 三、权限层（Group、Relationship）
-- ============================================================================

-- ==================== 用户组表 ====================
-- 用户组定义

CREATE TABLE IF NOT EXISTS t_group (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    group_id     VARCHAR(64)   NOT NULL COMMENT '组标识',
    service_id   VARCHAR(32)   NOT NULL COMMENT '所属服务',
    name         VARCHAR(128)  NOT NULL COMMENT '组名称',
    description  VARCHAR(512)  DEFAULT NULL COMMENT '组描述',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE group_id = ?
UNIQUE KEY uk_group_id (group_id),
    -- 按服务查询：WHERE service_id = ?
    INDEX idx_service_id (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户组';

-- ==================== 权限关系表 ====================
-- ReBAC 核心表：定义主体与资源之间的关系

CREATE TABLE IF NOT EXISTS t_relationship (
    _id            INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    service_id     VARCHAR(32)   NOT NULL COMMENT '所属服务',
    subject_type   VARCHAR(32)   NOT NULL COMMENT '主体类型：user/group/application',
    subject_id     VARCHAR(64)   NOT NULL COMMENT '主体 ID',
    relation       VARCHAR(32)   NOT NULL COMMENT '关系：admin/owner/editor/viewer/member',
    object_type    VARCHAR(32)   NOT NULL COMMENT '资源类型：service/recipe/category，* 表示全部',
    object_id      VARCHAR(128)  NOT NULL COMMENT '资源 ID，* 表示全部',
    -- 时间戳
    expires_at     DATETIME      DEFAULT NULL COMMENT '过期时间（NULL=永不过期）',
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

-- 索引
-- 唯一约束
UNIQUE KEY uk_relationship (service_id, subject_type, subject_id, relation, object_type, object_id),
    -- 权限检查（最高频）：WHERE service_id = ? AND subject_type = ? AND subject_id = ? AND object_type = ? AND object_id = ?
    INDEX idx_permission_check (service_id, subject_type, subject_id, object_type, object_id),
    -- 组成员查询：WHERE service_id = ? AND object_type = ? AND object_id = ? AND relation = ?
    INDEX idx_group_member (service_id, object_type, object_id, relation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='权限关系';