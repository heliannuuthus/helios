-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 域 ====================
INSERT INTO t_domain (domain_id, name, description) VALUES
('consumer', 'Consumer Identity', 'C端用户身份域'),
('platform', 'Platform Identity', 'B端平台身份域')
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description);

-- ==================== 域允许的 IDP ====================
INSERT INTO t_domain_idp (domain_id, idp_type) VALUES
('consumer', 'wechat-mp'),
('consumer', 'tt-mp'),
('consumer', 'alipay-mp'),
('consumer', 'wechat-web'),
('consumer', 'alipay-web'),
('consumer', 'tt-web'),
('consumer', 'user'),
('platform', 'github'),
('platform', 'google'),
('platform', 'staff'),
('platform', 'oper')
ON DUPLICATE KEY UPDATE domain_id = VALUES(domain_id);

-- ==================== 服务 ====================
INSERT INTO t_service (service_id, domain_id, name, description, access_token_expires_in, refresh_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', 7200, 604800),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 7200, 604800),
('zwei', '-', 'Zwei 菜谱服务', '菜谱管理、收藏、推荐服务', 7200, 604800),
('chaos', '-', 'Chaos 聚合服务', '邮件发送、文件上传等业务聚合服务', 7200, 604800)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), domain_id = VALUES(domain_id);

-- ==================== 服务密钥 ====================
DELETE FROM t_key WHERE owner_type = 'service';
INSERT INTO t_key (owner_type, owner_id, encrypted_key) VALUES
('service', 'hermes', 'Kv6P/3hgyxj9LQ4yj1QYvOIg16LGV1+Bqms+jLx8fr656ua68bibFo+6QuxC9dvtysODnuM9fXRVWMAWSgA5DJTE2zXYYm5Rp5Urmg=='),
('service', 'iris', 'BMfMVr3rgDQgrzuO+UgLVWjnZwvNWY+HettwRHi5tu9If1UoIjgGZLIMFO2PH6kii54ezzNj5RWXhPd+fcckzoxWjO2I7gdiVA0oIA=='),
('service', 'zwei', 'zA78tg/Aa78HRgvOiNeoiNSzubkJLatFebJbV1lcqJSQI7+AUx51yjdMs3gSCJ3hQ/KW7nfnBfoUy8iE8TWDCS0fUq/TapibBV52BQ=='),
('service', 'chaos', 'dPeKUwR0RAsXuiAo+0ueG2CRqE2h91lOcQYqMDyzKL+ZTaNXTVpS9YGaxItf/p2alCqrX6SFpljk/bD/6SalQKe7z5BwB9AqvbVnLQ==')
;

-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_origins) VALUES
('atlas', 'platform', 'Atlas 管理控制台', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]'),
('zwei', 'platform', 'Zwei 菜谱管理', NULL, '["https://zwei.heliannuuthus.com/auth/callback"]', '["https://zwei.heliannuuthus.com"]'),
('hermes', 'platform', 'Hermes 身份管理', NULL, '["https://hermes.heliannuuthus.com/auth/callback"]', '["https://hermes.heliannuuthus.com"]'),
('chaos', 'platform', 'Chaos 聚合服务', NULL, '["https://chaos.heliannuuthus.com/auth/callback"]', '["https://chaos.heliannuuthus.com"]'),
('piris', 'platform', '平台个人中心', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]'),
('ciris', 'consumer', '用户个人中心', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]')
ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins);

-- ==================== 应用 IDP 配置 ====================
INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES
('atlas', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('atlas', 'google', 5, NULL, NULL, NULL),
('atlas', 'github', 5, NULL, NULL, NULL),
('zwei', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('zwei', 'google', 5, NULL, NULL, NULL),
('zwei', 'github', 5, NULL, NULL, NULL),
('hermes', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('hermes', 'google', 5, NULL, NULL, NULL),
('hermes', 'github', 5, NULL, NULL, NULL),
('chaos', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('chaos', 'google', 5, NULL, NULL, NULL),
('chaos', 'github', 5, NULL, NULL, NULL),
('piris', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('piris', 'google', 5, NULL, NULL, NULL),
('piris', 'github', 5, NULL, NULL, NULL),
('ciris', 'user', 10, 'password', 'sms_otp', NULL),
('ciris', 'wechat-mp', 5, NULL, NULL, NULL),
('ciris', 'wechat-web', 5, NULL, NULL, NULL)
ON DUPLICATE KEY UPDATE priority = VALUES(priority), strategy = VALUES(strategy), delegate = VALUES(delegate), `require` = VALUES(`require`);

-- ==================== 应用服务关系 ====================
INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES
('atlas', 'hermes', '*'),
('atlas', 'zwei', '*'),
('atlas', 'chaos', '*'),
('zwei', 'zwei', '*'),
('hermes', 'hermes', '*'),
('chaos', 'chaos', '*'),
('piris', 'iris', '*'),
('ciris', 'iris', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);

-- ==================== 服务 Challenge 配置 ====================
INSERT INTO t_service_challenge_setting (service_id, `type`, expires_in, limits) VALUES
('iris', 'staff:verify', 300, '{"1m": 1, "24h": 10}'),
('iris', 'user:verify', 300, '{"1m": 1, "24h": 10}'),
('iris', 'passkey:verify', 300, '{"1m": 1, "24h": 10}')
ON DUPLICATE KEY UPDATE expires_in = VALUES(expires_in), limits = VALUES(limits);

-- ==================== 用户 ====================
INSERT INTO t_user (openid, status, username, password_hash, email_verified, nickname, picture, email) VALUES
('d6a3f7a078e3d656a3ccc350ffebf720', 0, 'heliannuuthus', '$2b$10$kln7iJp2rpDelUsDPm2FIeHLtqfOQtUQfkkFEHDMIdnrBQ7LElNT2', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO t_user_identity (domain, uid, idp, t_openid) VALUES
('platform', 'd6a3f7a078e3d656a3ccc350ffebf720', 'global', 'd6a3f7a078e3d656a3ccc350ffebf720'),
('platform', 'd6a3f7a078e3d656a3ccc350ffebf720', 'staff', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'd6a3f7a078e3d656a3ccc350ffebf720', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);