-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 域 ====================
INSERT INTO
    t_domain (domain_id, name, description)
VALUES (
        'consumer',
        '用户身份域',
        'C 端用户身份与权限隔离边界'
    ),
    (
        'platform',
        '平台身份域',
        'B 端平台身份与权限隔离边界'
    )
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    description = VALUES(description);

-- ==================== 域允许的 IDP ====================
INSERT INTO
    t_domain_idp (domain_id, idp_type)
VALUES ('consumer', 'wxmp'),
    ('consumer', 'ttmp'),
    ('consumer', 'almp'),
    ('consumer', 'wechat'),
    ('consumer', 'alipay'),
    ('consumer', 'tt'),
    ('consumer', 'user'),
    ('platform', 'github'),
    ('platform', 'google'),
    ('platform', 'staff'),
    ('platform', 'oper')
ON DUPLICATE KEY UPDATE
    domain_id = VALUES(domain_id);

-- ==================== 服务 ====================
INSERT INTO
    t_service (
        service_id,
        domain_id,
        name,
        description,
        logo_url,
        access_token_expires_in
    )
VALUES (
        'hermes',
        '-',
        'Hermes 管理服务',
        '身份与访问管理服务',
        'https://aegis.heliannuuthus.com/logos/hermes.svg',
        7200
    ),
    (
        'iris',
        '-',
        'Iris 用户服务',
        '用户信息管理服务',
        'https://aegis.heliannuuthus.com/logos/iris.svg',
        7200
    ),
    (
        'zwei',
        'platform',
        'Zwei 菜谱服务',
        '菜谱管理、收藏、推荐服务',
        'https://aegis.heliannuuthus.com/logos/zwei.svg',
        7200
    ),
    (
        'chaos',
        'platform',
        'Chaos 聚合服务',
        '邮件发送、文件上传等业务聚合服务',
        'https://aegis.heliannuuthus.com/logos/chaos.svg',
        7200
    )
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    description = VALUES(description),
    logo_url = VALUES(logo_url),
    domain_id = VALUES(domain_id);

-- ==================== 域密钥 & 服务密钥 ====================
DELETE FROM t_key WHERE owner_type IN ('domain', 'service');

INSERT INTO
    t_key (
        owner_type,
        owner_id,
        encrypted_key
    )
VALUES (
        'domain',
        'consumer',
        'bnLyZjTkxyU2enJDwp/KbG+XbGBOx1EmhP8vhNhRRrKwycZQUrYGqyMfazdT9Yu9wRiK43/1XRLDdZzBQWUeUcNkTH043OiUQryflA=='
    ),
    (
        'domain',
        'platform',
        'ZTcww9hP0YgrgxXgHkGOBgHqWezNUCRaoP3RbECzRD6sfup8UjEpEko2OfxIbHF+D2vaXXm2Z7ZT+tr3wev06agxARfiwE70BdMRQQ=='
    ),
    (
        'service',
        'hermes',
        'aAVU3Zo7y4WK8r4SVOSW6Vqtp6Yzk6R0juqVBLITesgjhJpgqHiK+UmA13IhXCrwJbdBW95RbXsnMEvwLZjlSk+st3IdryxgRw9UIw=='
    ),
    (
        'service',
        'iris',
        '18cmMegT5H2LiDJzVBHUkrfofoDzuusT8Try2XEo/oe0fpsmjeZGdcdDmeTeIeBWoAgmFJj7HZlKOxxkfNkAv0ovHtRQgB1D01daBw=='
    ),
    (
        'service',
        'zwei',
        '7iAw7lklVF7EmTFjhcOgXWHQZFtEvUjX3UYITkVKyXDSkHSPiK7NbWUF+ZQFVIm+5euBrFmWTVcJ7Hj4DdhRiGcNrGVNyJ69Zvl/4w=='
    ),
    (
        'service',
        'chaos',
        'XjLqTUNsYDMc95x2HN9mQIWNlX2zLZv1YZVZZhcISsU78RPLmQjS3rQunDr8hI4Yiww1/icDxgFN7qMVWY5tFnUiTihsn4zM2o8OBw=='
    );

-- ==================== 应用 ====================
INSERT INTO
    t_application (
        app_id,
        domain_id,
        name,
        description,
        logo_url,
        redirect_uris,
        allowed_origins,
        allowed_logout_uris,
        id_token_expires_in,
        refresh_token_expires_in,
        refresh_token_absolute_expires_in
    )
VALUES (
        'atlas',
        'platform',
        'Atlas 管理控制台',
        'Hermes 身份与访问管理系统的官方管理后台，支持域、应用、服务及关系的配置与可视化管理。',
        'https://aegis.heliannuuthus.com/logos/atlas.svg',
        '["https://atlas.heliannuuthus.com/auth/callback"]',
        '["https://atlas.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    ),
    (
        'zwei',
        'platform',
        'Zwei 菜谱管理',
        '企业级菜谱管理与分发系统，集成 Hermes 实现细粒度的权限控制。',
        NULL,
        '["https://zwei.heliannuuthus.com/auth/callback"]',
        '["https://zwei.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    ),
    (
        'hermes',
        'platform',
        'Hermes 身份管理',
        '身份验证与授权中心，提供 OIDC/OAuth2 协议支持与 ReBAC 鉴权能力。',
        NULL,
        '["https://hermes.heliannuuthus.com/auth/callback"]',
        '["https://hermes.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    ),
    (
        'chaos',
        'platform',
        'Chaos 聚合服务',
        '业务支撑聚合系统，包含邮件、短信、文件存储等通用能力模块。',
        NULL,
        '["https://chaos.heliannuuthus.com/auth/callback"]',
        '["https://chaos.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    ),
    (
        'piris',
        'platform',
        '平台个人中心',
        'B 端员工个人信息管理与安全设置中心。',
        NULL,
        '["https://iris.heliannuuthus.com/auth/callback"]',
        '["https://iris.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    ),
    (
        'ciris',
        'consumer',
        '用户个人中心',
        'C 端外部用户个人账号管理与偏好设置中心。',
        NULL,
        '["https://iris.heliannuuthus.com/auth/callback"]',
        '["https://iris.heliannuuthus.com"]',
        NULL,
        3600,
        604800,
        0
    )
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    description = VALUES(description),
    logo_url = VALUES(logo_url),
    redirect_uris = VALUES(redirect_uris),
    allowed_origins = VALUES(allowed_origins),
    allowed_logout_uris = VALUES(allowed_logout_uris),
    id_token_expires_in = VALUES(id_token_expires_in),
    refresh_token_expires_in = VALUES(refresh_token_expires_in),
    refresh_token_absolute_expires_in = VALUES(
        refresh_token_absolute_expires_in
    );

-- ==================== 应用 IDP 配置 ====================
INSERT INTO
    t_application_idp_config (
        app_id,
        `type`,
        priority,
        strategy,
        delegate,
        `require`
    )
VALUES (
        'atlas',
        'staff',
        10,
        'password',
        'email_otp,webauthn',
        'captcha'
    ),
    (
        'atlas',
        'google',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'atlas',
        'github',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'zwei',
        'staff',
        10,
        'password',
        'email_otp,webauthn',
        'captcha'
    ),
    (
        'zwei',
        'google',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'zwei',
        'github',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'hermes',
        'staff',
        10,
        'password',
        'email_otp,webauthn',
        'captcha'
    ),
    (
        'hermes',
        'google',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'hermes',
        'github',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'chaos',
        'staff',
        10,
        'password',
        'email_otp,webauthn',
        'captcha'
    ),
    (
        'chaos',
        'google',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'chaos',
        'github',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'piris',
        'staff',
        10,
        'password',
        'email_otp,webauthn',
        'captcha'
    ),
    (
        'piris',
        'google',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'piris',
        'github',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'ciris',
        'user',
        10,
        'password',
        'sms_otp',
        NULL
    ),
    (
        'ciris',
        'wxmp',
        5,
        NULL,
        NULL,
        NULL
    ),
    (
        'ciris',
        'wechat',
        5,
        NULL,
        NULL,
        NULL
    )
ON DUPLICATE KEY UPDATE
    priority = VALUES(priority),
    strategy = VALUES(strategy),
    delegate = VALUES(delegate),
    `require` = VALUES(`require`);

-- ==================== 应用服务关系 ====================
INSERT INTO
    t_application_service_relation (app_id, service_id, relation)
VALUES ('atlas', 'hermes', '*'),
    ('atlas', 'zwei', '*'),
    ('atlas', 'chaos', '*'),
    ('zwei', 'zwei', '*'),
    ('hermes', 'hermes', '*'),
    ('chaos', 'chaos', '*'),
    ('piris', 'iris', '*'),
    ('ciris', 'iris', '*')
ON DUPLICATE KEY UPDATE
    relation = VALUES(relation);

-- ==================== 服务 Challenge 配置 ====================
INSERT INTO
    t_service_challenge_setting (
        service_id,
        `type`,
        expires_in,
        limits
    )
VALUES (
        'iris',
        'staff:verify',
        300,
        '{"1m": 1, "24h": 10}'
    ),
    (
        'iris',
        'user:verify',
        300,
        '{"1m": 1, "24h": 10}'
    ),
    (
        'iris',
        'passkey:verify',
        300,
        '{"1m": 1, "24h": 10}'
    )
ON DUPLICATE KEY UPDATE
    expires_in = VALUES(expires_in),
    limits = VALUES(limits);

-- ==================== 用户 ====================
INSERT INTO
    t_user (
        openid,
        status,
        username,
        password_hash,
        email_verified,
        nickname,
        picture,
        email
    )
VALUES (
        '11ffa2fb5bfa3b8f8e805d88c479f306',
        0,
        'heliannuuthus',
        '$2b$10$D8oUvB0Gh1mlaWxwetozSeBKqIqLk1viyoz6e5iIXkFKt.48.W.WW',
        1,
        'Heliannuuthus',
        NULL,
        'heliannuuthus@gmail.com'
    )
ON DUPLICATE KEY UPDATE
    nickname = VALUES(nickname),
    email = VALUES(email),
    email_verified = VALUES(email_verified),
    username = VALUES(username),
    password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO
    t_user_identity (domain, uid, idp, t_openid)
VALUES (
        'platform',
        '11ffa2fb5bfa3b8f8e805d88c479f306',
        'global',
        '11ffa2fb5bfa3b8f8e805d88c479f306'
    ),
    (
        'platform',
        '11ffa2fb5bfa3b8f8e805d88c479f306',
        'staff',
        'heliannuuthus'
    )
ON DUPLICATE KEY UPDATE
    t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO
    t_relationship (
        service_id,
        subject_type,
        subject_id,
        relation,
        object_type,
        object_id
    )
VALUES (
        'hermes',
        'user',
        '11ffa2fb5bfa3b8f8e805d88c479f306',
        'admin',
        '*',
        '*'
    )
ON DUPLICATE KEY UPDATE
    relation = VALUES(relation);