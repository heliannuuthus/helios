-- Hermes 数据库 Schema（身份与访问管理数据）
-- MySQL 8.0+ 语法
-- 注意：session、authorization_code、refresh_token 都存储在 Redis 中
-- 注意：Domain 配置从配置文件读取，不需要建表
-- 注意：IDP 配置从配置文件读取，不需要建表

-- ==================== 数据库初始化 ====================

CREATE DATABASE IF NOT EXISTS `hermes` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON `hermes`.* TO 'helios' @'%';

FLUSH PRIVILEGES;

USE `hermes`;

-- ============================================================================
-- 一、平台配置层（Domain > Application > Service）
-- ============================================================================

-- ==================== 应用表 ====================
-- OAuth2 客户端应用，属于某个 Domain

CREATE TABLE IF NOT EXISTS t_application (
    _id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain_id          VARCHAR(32)   NOT NULL COMMENT '所属域：ciam/piam',
    app_id             VARCHAR(64)   NOT NULL COMMENT '应用唯一标识',
    name               VARCHAR(128)  NOT NULL COMMENT '应用名称',
    logo_url           VARCHAR(512)  DEFAULT NULL COMMENT '应用 Logo URL',
    encrypted_key      VARCHAR(256)  DEFAULT NULL COMMENT '应用密钥（AES-GCM 加密），NULL=公开应用',
    redirect_uris      VARCHAR(2048) DEFAULT NULL COMMENT '重定向 URI 列表（JSON 数组）',
    allowed_origins    VARCHAR(1024) DEFAULT NULL COMMENT '允许的跨域源（JSON 数组）',
    -- 时间戳
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE app_id = ?
UNIQUE KEY uk_app_id (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth2 应用';

-- ==================== 应用 IDP 配置表 ====================
-- 应用级别的 IDP 配置（登录方式、委托验证、前置验证）

CREATE TABLE IF NOT EXISTS t_application_idp_config (
    _id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    app_id       VARCHAR(64)  NOT NULL COMMENT '应用 ID',
    `type`       VARCHAR(32)  NOT NULL COMMENT 'IDP 类型：github/google/wechat-mp/user/oper',
    priority     INT          NOT NULL DEFAULT 0 COMMENT '排序优先级（值越大越靠前）',
    strategy     VARCHAR(256) DEFAULT NULL COMMENT '认证方式（仅 user/oper）：password,webauthn',
    delegate     VARCHAR(256) DEFAULT NULL COMMENT '委托 MFA：email_otp,totp,webauthn',
    `require`    VARCHAR(256) DEFAULT NULL COMMENT '前置验证：captcha',
    -- 时间戳
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE app_id = ? ORDER BY priority DESC
UNIQUE KEY uk_app_type (app_id, `type`),
    INDEX idx_app_priority (app_id, priority DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='应用 IDP 配置';

-- ==================== 服务表 ====================
-- 业务服务定义，每个服务有独立的密钥和 Token 配置

CREATE TABLE IF NOT EXISTS t_service (
    _id                       INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain_id                 VARCHAR(32)   NOT NULL COMMENT '所属域：ciam/piam，- 表示跨域',
    service_id                VARCHAR(32)   NOT NULL COMMENT '服务标识：hermes/zwei/order',
    name                      VARCHAR(128)  NOT NULL COMMENT '服务名称',
    description               VARCHAR(512)  DEFAULT NULL COMMENT '服务描述',
    encrypted_key             VARCHAR(256)  NOT NULL COMMENT '服务密钥（AES-GCM 加密，Base64 编码）',
    access_token_expires_in   INT UNSIGNED  NOT NULL DEFAULT 7200 COMMENT 'Access Token 有效期（秒）',
    refresh_token_expires_in  INT UNSIGNED  NOT NULL DEFAULT 604800 COMMENT 'Refresh Token 有效期（秒）',
    required_identities       VARCHAR(512)  DEFAULT NULL COMMENT '访问需要的身份类型（JSON 数组）',
    -- 时间戳
    created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 索引：主查询 WHERE service_id = ?
UNIQUE KEY uk_service_id (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='业务服务';

-- ==================== 服务 Challenge 配置表 ====================
-- 服务级别的 Challenge 配置（限流等），覆盖全局默认

CREATE TABLE IF NOT EXISTS t_service_challenge_config (
    _id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    service_id   VARCHAR(32)  NOT NULL COMMENT '服务 ID',
    `type`       VARCHAR(64)  NOT NULL COMMENT 'Challenge 类型[:场景]，如 email_otp / email_otp:login',
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
-- 注意：domain 的概念由 t_user_identity 中的主身份（user/oper）承载，不在 t_user 表中存储

CREATE TABLE IF NOT EXISTS t_user (
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    uid              VARCHAR(64)   NOT NULL COMMENT '用户内部关联 ID（不对外暴露）',
    status           TINYINT       NOT NULL DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
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
-- 主查询：WHERE uid = ?
UNIQUE KEY uk_uid (uid),
    -- 登录查询：WHERE email = ? / WHERE phone = ?
    UNIQUE KEY uk_email (email),
    UNIQUE KEY uk_phone (phone)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户';

-- ==================== 用户身份表 ====================
-- 用户与 IDP 的绑定关系，每个身份归属一个域（ciam/piam）
-- idp=global 的身份为该域下的对外标识（token 中的 sub）

CREATE TABLE IF NOT EXISTS t_user_identity (
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    domain       VARCHAR(16)   NOT NULL COMMENT '身份所属域：ciam/piam',
    uid          VARCHAR(64)   NOT NULL COMMENT '用户内部标识（关联 t_user.uid）',
    idp          VARCHAR(64)   NOT NULL COMMENT 'IDP 标识：global/user/oper/github/wechat-mp/google 等',
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
    CONSTRAINT fk_identity_user FOREIGN KEY (uid) REFERENCES t_user(uid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户身份';

-- ==================== 用户凭证表 ====================
-- 用户安全凭证（MFA：TOTP、WebAuthn、Passkey）

CREATE TABLE IF NOT EXISTS t_user_credential (
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 业务字段
    uid              VARCHAR(64)   NOT NULL COMMENT '用户唯一标识（关联 t_user.uid）',
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
    -- 查询用户凭证：WHERE uid = ? AND type = ?
    INDEX idx_uid_type (uid, `type`)
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