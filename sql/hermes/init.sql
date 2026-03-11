-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 域 ====================
INSERT INTO t_domain (domain_id, name, description) VALUES
('consumer', '用户身份域', 'C 端用户身份与权限隔离边界'),
('platform', '平台身份域', 'B 端平台身份与权限隔离边界')
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
INSERT INTO t_service (service_id, domain_id, name, description, logo_url, access_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', 'https://aegis.heliannuuthus.com/logos/hermes.svg', 7200),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'https://aegis.heliannuuthus.com/logos/iris.svg', 7200),
('zwei', 'platform', 'Zwei 菜谱服务', '菜谱管理、收藏、推荐服务', 'https://aegis.heliannuuthus.com/logos/zwei.svg', 7200),
('chaos', 'platform', 'Chaos 聚合服务', '邮件发送、文件上传等业务聚合服务', 'https://aegis.heliannuuthus.com/logos/chaos.svg', 7200)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), logo_url = VALUES(logo_url), domain_id = VALUES(domain_id);

-- ==================== 域密钥 & 服务密钥 ====================
DELETE FROM t_key WHERE owner_type IN ('domain', 'service');
INSERT INTO t_key (owner_type, owner_id, encrypted_key) VALUES
('domain', 'consumer', 'a4NqgAm7q8/B5qsrx5xz2JxJBWZtaC02+0CIjzu1GHrI5LVRBUdIsASkpjIVzOaYO2Om7/DVxjo7wpznyOK4zk2kTpzL4Fva6w+pyw=='),
('domain', 'platform', '37J5LQrYndbsmM+e4avG1sB4DcdgQ6rML8/2L3R0ICmvHHJIXGw9TrYiK1LV7wtGbPwEMUg+DFo8jVC697mvAzPvUfUWiybWcdB5mA=='),
('service', 'hermes', 'JLikg1HxtUWsRQp2F8muoAwe/xBAu+vLS4ywFY6IU3+lU4C/rmcP3OeH86R2vTqnhIVWayIijRNTf8JfyZjDXvvhnu8G3un6iOVBQA=='),
('service', 'iris', '287sdBoaQi0K2KN1+lwpQFzCzc13Xeno+tNIBLqoYBYcctfKmxtBJYGqrfjcfN2xLQdcSYjPal1JMbfbFiTSBIp06F6qwCDs6N1DEA=='),
('service', 'zwei', 'Uqqp44pD79g873HQv2PyzQ+WpCUU9LnPTlGF3bF2WAjLt7vXEfc7v0Odfg/wpXO7I7zuzXN96Z6aWHfsp7+/mwluVZ/qLnuw+etkLw=='),
('service', 'chaos', 'lhVDRFtSPyItPUYwNsfEFb+F9IuogYvAOTIGs47LKyFmr8TeCFvfIZFB2iqAJX9sihwHxDjM6VDQ6zJ8VaMy+UTbOmiC9yCI8gWOXQ==')
;

-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, description, logo_url, redirect_uris, allowed_origins, id_token_expires_in, refresh_token_expires_in, refresh_token_absolute_expires_in) VALUES
('atlas', 'platform', 'Atlas 管理控制台', 'Hermes 身份与访问管理系统的官方管理后台，支持域、应用、服务及关系的配置与可视化管理。', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]', 3600, 604800, 0),
('zwei', 'platform', 'Zwei 菜谱管理', '企业级菜谱管理与分发系统，集成 Hermes 实现细粒度的权限控制。', NULL, '["https://zwei.heliannuuthus.com/auth/callback"]', '["https://zwei.heliannuuthus.com"]', 3600, 604800, 0),
('hermes', 'platform', 'Hermes 身份管理', '身份验证与授权中心，提供 OIDC/OAuth2 协议支持与 ReBAC 鉴权能力。', NULL, '["https://hermes.heliannuuthus.com/auth/callback"]', '["https://hermes.heliannuuthus.com"]', 3600, 604800, 0),
('chaos', 'platform', 'Chaos 聚合服务', '业务支撑聚合系统，包含邮件、短信、文件存储等通用能力模块。', NULL, '["https://chaos.heliannuuthus.com/auth/callback"]', '["https://chaos.heliannuuthus.com"]', 3600, 604800, 0),
('piris', 'platform', '平台个人中心', 'B 端员工个人信息管理与安全设置中心。', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]', 3600, 604800, 0),
('ciris', 'consumer', '用户个人中心', 'C 端外部用户个人账号管理与偏好设置中心。', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]', 3600, 604800, 0)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins), id_token_expires_in = VALUES(id_token_expires_in), refresh_token_expires_in = VALUES(refresh_token_expires_in), refresh_token_absolute_expires_in = VALUES(refresh_token_absolute_expires_in);

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
('5fb6700fd625a0854b80e5e07932f365', 0, 'heliannuuthus', '$2b$10$IydKmonsoml6jcSh3ZY7/uy/2ZRTHEtf4Mf1dskTWAbiukd71lpEm', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO t_user_identity (domain, uid, idp, t_openid) VALUES
('platform', '5fb6700fd625a0854b80e5e07932f365', 'global', '5fb6700fd625a0854b80e5e07932f365'),
('platform', '5fb6700fd625a0854b80e5e07932f365', 'staff', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', '5fb6700fd625a0854b80e5e07932f365', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);