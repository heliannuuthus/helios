-- Auth 模块数据库表结构

-- 客户端表
CREATE TABLE IF NOT EXISTS t_auth_client (
    id VARCHAR(64) PRIMARY KEY COMMENT '客户端 ID',
    name VARCHAR(128) NOT NULL COMMENT '客户端名称',
    domain VARCHAR(32) NOT NULL COMMENT '所属域：ciam/piam',
    access_token_expires_in INT DEFAULT 7200 COMMENT 'Access Token 有效期（秒）',
    refresh_token_expires_in INT DEFAULT 604800 COMMENT 'Refresh Token 有效期（秒）',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth2 客户端';

-- 客户端重定向 URI
CREATE TABLE IF NOT EXISTS t_auth_client_redirect_uri (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL COMMENT '客户端 ID',
    uri VARCHAR(512) NOT NULL COMMENT '重定向 URI',
    INDEX idx_client_id (client_id),
    CONSTRAINT fk_redirect_uri_client FOREIGN KEY (client_id) REFERENCES t_auth_client(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='客户端重定向 URI';

-- 客户端允许的 IDP
CREATE TABLE IF NOT EXISTS t_auth_client_idp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL COMMENT '客户端 ID',
    idp VARCHAR(64) NOT NULL COMMENT 'IDP 标识',
    INDEX idx_client_id (client_id),
    UNIQUE KEY uk_client_idp (client_id, idp),
    CONSTRAINT fk_idp_client FOREIGN KEY (client_id) REFERENCES t_auth_client(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='客户端允许的 IDP';

-- 用户表
CREATE TABLE IF NOT EXISTS t_auth_user (
    id VARCHAR(64) PRIMARY KEY COMMENT '用户 ID',
    domain VARCHAR(32) NOT NULL COMMENT '所属域：ciam/piam',
    name VARCHAR(128) COMMENT '昵称',
    picture VARCHAR(512) COMMENT '头像 URL',
    phone VARCHAR(64) COMMENT '手机号哈希',
    phone_cipher VARCHAR(256) COMMENT '手机号密文',
    status TINYINT DEFAULT 0 COMMENT '状态：0=active, 1=disabled',
    last_login_at DATETIME COMMENT '最后登录时间',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_phone (phone),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户';

-- 用户身份表（IDP 绑定）
CREATE TABLE IF NOT EXISTS t_auth_user_identity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL COMMENT '用户 ID',
    idp VARCHAR(64) NOT NULL COMMENT 'IDP 标识',
    provider_id VARCHAR(256) NOT NULL COMMENT 'IDP 返回的用户标识',
    union_id VARCHAR(256) COMMENT '联合 ID（微信 UnionID 等）',
    raw_data TEXT COMMENT 'IDP 返回的原始数据',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_idp_provider (idp, provider_id),
    INDEX idx_user_id (user_id),
    INDEX idx_union_id (union_id),
    CONSTRAINT fk_identity_user FOREIGN KEY (user_id) REFERENCES t_auth_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户身份';

-- Refresh Token 表
CREATE TABLE IF NOT EXISTS t_auth_refresh_token (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(128) NOT NULL COMMENT 'Refresh Token',
    user_id VARCHAR(64) NOT NULL COMMENT '用户 ID',
    client_id VARCHAR(64) NOT NULL COMMENT '客户端 ID',
    scope VARCHAR(256) COMMENT 'Scope',
    expires_at DATETIME NOT NULL COMMENT '过期时间',
    revoked TINYINT(1) DEFAULT 0 COMMENT '是否已撤销',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_token (token),
    INDEX idx_user_id (user_id),
    INDEX idx_client_id (client_id),
    INDEX idx_expires_at (expires_at),
    CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES t_auth_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Refresh Token';

-- 初始化示例客户端
INSERT INTO t_auth_client (id, name, domain, access_token_expires_in, refresh_token_expires_in)
VALUES 
    ('zwei-mp', 'Zwei 小程序', 'ciam', 7200, 31536000),
    ('atlas-web', 'Atlas 中台', 'piam', 7200, 2592000)
ON DUPLICATE KEY UPDATE updated_at = NOW();

-- Zwei 小程序的重定向 URI
INSERT INTO t_auth_client_redirect_uri (client_id, uri) VALUES
    ('zwei-mp', 'https://servicewechat.com/callback')
ON DUPLICATE KEY UPDATE uri = VALUES(uri);

-- Zwei 小程序允许的 IDP
INSERT INTO t_auth_client_idp (client_id, idp) VALUES
    ('zwei-mp', 'wechat:mp'),
    ('zwei-mp', 'tt:mp'),
    ('zwei-mp', 'alipay:mp')
ON DUPLICATE KEY UPDATE idp = VALUES(idp);

-- Atlas 中台的重定向 URI
INSERT INTO t_auth_client_redirect_uri (client_id, uri) VALUES
    ('atlas-web', 'http://localhost:5173/callback'),
    ('atlas-web', 'https://atlas.example.com/callback')
ON DUPLICATE KEY UPDATE uri = VALUES(uri);

-- Atlas 中台允许的 IDP
INSERT INTO t_auth_client_idp (client_id, idp) VALUES
    ('atlas-web', 'github'),
    ('atlas-web', 'google'),
    ('atlas-web', 'wecom')
ON DUPLICATE KEY UPDATE idp = VALUES(idp);
