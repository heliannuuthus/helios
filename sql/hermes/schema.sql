-- Hermes 数据库 Schema（身份与访问管理数据）
-- MySQL 8.0+ 语法
-- 注意：session、authorization_code、refresh_token 都存储在 Redis 中
-- 注意：IDP 配置从配置文件读取，不需要建表
-- 注意：Domain 配置从配置文件读取，不需要建表

-- ==================== 数据库初始化 ====================

CREATE DATABASE IF NOT EXISTS `hermes` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 授予用户权限（MYSQL_USER 环境变量创建的用户，默认用户名是 helios）
GRANT ALL PRIVILEGES ON `hermes`.* TO 'helios'@'%';
FLUSH PRIVILEGES;

USE `hermes`;

-- ==================== 服务表 ====================
-- 业务服务定义，每个服务有独立的密钥和 Token 配置

CREATE TABLE IF NOT EXISTS t_service (
    -- 主键
    _id                       INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段（按访问频率排序）
    service_id                VARCHAR(32)   NOT NULL COMMENT '服务标识：hermes/zwei/order',
    domain_id                 VARCHAR(32)   NOT NULL COMMENT '所属域：ciam/piam',
    access_token_expires_in   INT UNSIGNED  NOT NULL DEFAULT 7200 COMMENT 'Access Token 有效期（秒）',
    refresh_token_expires_in  INT UNSIGNED  NOT NULL DEFAULT 604800 COMMENT 'Refresh Token 有效期（秒）',
    -- 时间戳字段
    created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段
    name                      VARCHAR(128)  NOT NULL COMMENT '服务名称',
    description               VARCHAR(512)  DEFAULT NULL COMMENT '服务描述',
    encrypted_key             VARCHAR(256)  NOT NULL COMMENT '服务密钥（AES-GCM 加密，Base64 编码）',
    required_identities       VARCHAR(512)  DEFAULT NULL COMMENT '访问需要的身份类型（JSON 数组）',

    -- 索引
    UNIQUE KEY uk_service_id (service_id),
    INDEX idx_domain_id (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='业务服务';


-- ==================== 应用表 ====================
-- OAuth2 客户端应用

CREATE TABLE IF NOT EXISTS t_application (
    -- 主键
    _id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段
    app_id             VARCHAR(64)   NOT NULL COMMENT '应用唯一标识',
    domain_id          VARCHAR(32)   NOT NULL COMMENT '所属域：ciam/piam',
    -- 时间戳字段
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段
    name               VARCHAR(128)  NOT NULL COMMENT '应用名称',
    logo_url           VARCHAR(512)  DEFAULT NULL COMMENT '应用 Logo URL',
    encrypted_key      VARCHAR(256)  DEFAULT NULL COMMENT '应用密钥（AES-GCM 加密），NULL=公开应用',
    redirect_uris      VARCHAR(2048) DEFAULT NULL COMMENT '重定向 URI 列表（JSON 数组）',
    allowed_idps       VARCHAR(512)  DEFAULT NULL COMMENT '允许的登录方式（JSON 数组）',
    allowed_origins    VARCHAR(1024) DEFAULT NULL COMMENT '允许的跨域源（JSON 数组）',

    -- 索引
    UNIQUE KEY uk_app_id (app_id),
    INDEX idx_domain_id (domain_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth2 应用';


-- ==================== 应用服务关系表 ====================
-- 定义应用可以访问哪些服务的哪些关系

CREATE TABLE IF NOT EXISTS t_application_service_relation (
    -- 主键
    _id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段
    app_id       VARCHAR(64)  NOT NULL COMMENT '应用 ID',
    service_id   VARCHAR(32)  NOT NULL COMMENT '服务 ID',
    relation     VARCHAR(32)  NOT NULL DEFAULT '*' COMMENT '允许的关系，* 表示全部',
    -- 时间戳
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- 索引
    -- 主查询：通过 app_id 查找可访问的服务
    UNIQUE KEY uk_app_service_relation (app_id, service_id, relation),
    -- 反向查询：通过 service_id 查找哪些应用可访问
    INDEX idx_service_id (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='应用服务关系';


-- ==================== 用户表 ====================
-- 用户基本信息

CREATE TABLE IF NOT EXISTS t_user (
    -- 主键
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段（高频访问）
    openid           VARCHAR(64)   NOT NULL COMMENT '用户唯一标识',
    domain_id        VARCHAR(32)   NOT NULL COMMENT '所属域：ciam/piam',
    status           TINYINT       NOT NULL DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    email_verified   TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '邮箱是否已验证',
    -- 时间戳字段
    last_login_at    DATETIME      DEFAULT NULL COMMENT '最后登录时间',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段（低频访问）
    nickname         VARCHAR(128)  DEFAULT NULL COMMENT '昵称',
    picture          VARCHAR(512)  DEFAULT NULL COMMENT '头像 URL',
    email            VARCHAR(256)  DEFAULT NULL COMMENT '邮箱（明文）',
    phone            VARCHAR(64)   DEFAULT NULL COMMENT '手机号哈希（SHA256，用于查询）',
    phone_cipher     VARCHAR(256)  DEFAULT NULL COMMENT '手机号密文（AES-GCM）',

    -- 索引
    UNIQUE KEY uk_openid (openid),
    -- 邮箱/手机号唯一（允许 NULL，MySQL 8.0+ NULL 不参与唯一约束）
    UNIQUE KEY uk_email (email),
    UNIQUE KEY uk_phone (phone),
    -- 复合索引：按域查询活跃用户
    INDEX idx_domain_status (domain_id, status),
    -- 登录时间索引：用于清理/统计
    INDEX idx_last_login (last_login_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户';


-- ==================== 用户身份表 ====================
-- 用户与第三方 IDP 的绑定关系

CREATE TABLE IF NOT EXISTS t_user_identity (
    -- 主键
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段
    openid       VARCHAR(64)   NOT NULL COMMENT '用户标识（关联 t_user.openid）',
    idp          VARCHAR(64)   NOT NULL COMMENT 'IDP 标识：wechat:mp/github/google',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段
    t_openid     VARCHAR(256)  NOT NULL COMMENT '第三方用户标识（IDP 返回的 openid）',
    raw_data     TEXT          DEFAULT NULL COMMENT 'IDP 返回的原始数据（JSON）',

    -- 索引
    -- 主查询：通过 IDP + 第三方 ID 查找用户（登录场景）
    UNIQUE KEY uk_idp_t_openid (idp, t_openid),
    -- 查询用户绑定的所有身份
    INDEX idx_openid (openid),
    -- 外键约束：用户删除时级联删除身份
    CONSTRAINT fk_identity_user FOREIGN KEY (openid) REFERENCES t_user(openid) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户身份';


-- ==================== 权限关系表 ====================
-- ReBAC 核心表：定义主体与资源之间的关系

CREATE TABLE IF NOT EXISTS t_relationship (
    -- 主键
    _id            INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段（按查询频率排序）
    service_id     VARCHAR(32)   NOT NULL COMMENT '所属服务',
    subject_type   VARCHAR(32)   NOT NULL COMMENT '主体类型：user/group/application',
    subject_id     VARCHAR(64)   NOT NULL COMMENT '主体 ID',
    relation       VARCHAR(32)   NOT NULL COMMENT '关系：admin/owner/editor/viewer/member',
    object_type    VARCHAR(32)   NOT NULL COMMENT '资源类型：service/recipe/category，* 表示全部',
    object_id      VARCHAR(128)  NOT NULL COMMENT '资源 ID，* 表示全部',
    -- 时间戳
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     DATETIME      DEFAULT NULL COMMENT '过期时间（NULL=永不过期）',

    -- 索引
    -- 唯一约束：同一关系只能定义一次
    UNIQUE KEY uk_relationship (service_id, subject_type, subject_id, relation, object_type, object_id),
    -- 权限检查：查询主体对资源的权限（最高频查询）
    INDEX idx_permission_check (service_id, subject_type, subject_id, object_type, object_id),
    -- 反向查询：查询资源被哪些主体访问
    INDEX idx_object_lookup (service_id, object_type, object_id),
    -- 过期清理
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='权限关系';


-- ==================== 用户凭证表 ====================
-- 用户安全凭证（MFA：TOTP、WebAuthn、Passkey）

CREATE TABLE IF NOT EXISTS t_user_credential (
    -- 主键
    _id              INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段（高频访问）
    openid           VARCHAR(64)   NOT NULL COMMENT '用户唯一标识（关联 t_user）',
    credential_id    VARCHAR(256)  DEFAULT NULL COMMENT 'WebAuthn 凭证 ID（Base64 编码，用于认证查询）',
    type             VARCHAR(32)   NOT NULL COMMENT '凭证类型：totp/webauthn/passkey',
    enabled          TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '是否已启用（绑定验证后设为 1）',
    -- 时间戳字段
    last_used_at     DATETIME      DEFAULT NULL COMMENT '最后使用时间',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段
    secret           VARCHAR(2048) NOT NULL COMMENT '凭证数据（AES-GCM 加密，Base64 编码的 JSON）',

    -- 索引
    UNIQUE KEY uk_credential_id (credential_id),
    INDEX idx_openid (openid),
    INDEX idx_openid_type (openid, type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户安全凭证（MFA）';


-- ==================== 用户组表 ====================
-- 用户组定义

CREATE TABLE IF NOT EXISTS t_group (
    -- 主键
    _id          INT UNSIGNED  AUTO_INCREMENT PRIMARY KEY,
    -- 固定长度字段
    group_id     VARCHAR(64)   NOT NULL COMMENT '组标识',
    service_id   VARCHAR(32)   NOT NULL COMMENT '所属服务',
    -- 时间戳
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- 变长字段
    name         VARCHAR(128)  NOT NULL COMMENT '组名称',
    description  VARCHAR(512)  DEFAULT NULL COMMENT '组描述',

    -- 索引
    UNIQUE KEY uk_group_id (group_id),
    INDEX idx_service_id (service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户组';
