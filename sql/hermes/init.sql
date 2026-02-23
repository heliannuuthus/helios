-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 服务 ====================
INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', 'gDOjIs2MuyuhRu3Ac1MZqdLsqOzuAq4xvq+XMT4IElH7MRIkRoS7DFwLIHR9/ABLcF7NM42aPG+zliyK', 7200, 604800),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'SzQIqZy/iOpIUOjX41eJed3QsNcvPNVumm6Qs8rD5YVnrFqbot5KMwutyfhUAS9T8ZJAi5I4fgifGdgb', 7200, 604800)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);

-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_origins) VALUES
('atlas', 'platform', 'Atlas 管理控制台', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]'),
('piris', 'platform', '平台个人中心', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]'),
('ciris', 'consumer', '用户个人中心', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]')
ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins);

-- ==================== 应用 IDP 配置 ====================
INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES
('atlas', 'staff', 10, 'password', 'email_otp,webauthn', 'captcha'),
('atlas', 'google', 5, NULL, NULL, NULL),
('atlas', 'github', 5, NULL, NULL, NULL),
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
('piris', 'iris', '*'),
('ciris', 'iris', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);

-- ==================== Challenge 配置 ====================
INSERT INTO t_service_challenge_config (service_id, `type`, limits) VALUES
('hermes', 'verify', '{"1m": 1, "1h": 5, "24h": 10}'),
('hermes', 'forget_password', '{"1m": 1, "1h": 5, "24h": 10}'),
('iris', 'verify', '{"1m": 1, "1h": 5, "24h": 10}'),
('iris', 'forget_password', '{"1m": 1, "1h": 5, "24h": 10}')
ON DUPLICATE KEY UPDATE limits = VALUES(limits);

-- ==================== 用户 ====================
INSERT INTO t_user (openid, status, username, password_hash, email_verified, nickname, picture, email) VALUES
('heliannuuthus', 0, 'heliannuuthus', '$2b$10$jxNR8Mj8IEQ7ZlBwlJTXVuT1fbl5d2/VTJSli3WA/Pitg/tqBq3Za', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO t_user_identity (domain, openid, idp, t_openid) VALUES
('platform', 'heliannuuthus', 'global', 'fc55e87e9e108ae0892f7847f2a78fe0'),
('platform', 'heliannuuthus', 'staff', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'heliannuuthus', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);