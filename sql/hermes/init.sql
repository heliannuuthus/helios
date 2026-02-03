-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 应用 ====================
INSERT INTO t_application (domain_id, app_id, name, logo_url, redirect_uris, allowed_origins) VALUES
('piam', 'atlas', 'Atlas 管理控制台', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]')
ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins);

-- ==================== 应用 IDP 配置 ====================
-- strategy: 基础登录策略（如 password）
-- delegate: 可替代 strategy 的验证方式（如 email_otp, webauthn）
-- 用户可以选择 strategy 或 delegate 中的任一方式完成验证
INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES
('atlas', 'github', 10, NULL, NULL, NULL),
('atlas', 'google', 9, NULL, NULL, NULL),
('atlas', 'oper', 8, 'password', 'email_otp,webauthn', 'captcha')
ON DUPLICATE KEY UPDATE priority = VALUES(priority), strategy = VALUES(strategy), delegate = VALUES(delegate), `require` = VALUES(`require`);

-- ==================== 服务 ====================
-- domain_id = '-' 表示跨域内置服务，属于全部域
INSERT INTO t_service (domain_id, service_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES
('-', 'hermes', 'Hermes 管理服务', '身份与访问管理服务', 'HawIx3yfeIU5hkWPqM/dhiVJ682FB4/brPszu10g+URIIrd0V5d9UigiWEOK7groZJslch6bSYOi1ddl', 7200, 604800),
('-', 'iris', 'Iris 用户服务', '用户信息管理服务', 'EQC2OsWg80zU1WcpXAjHmlTtT/OsYh+Qwf4C5JgNxuG2c07YTxpE+c1hXlYacno34+M71jRlKCkdTD6Z', 7200, 604800)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);

-- ==================== 应用服务关系 ====================
INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES
('atlas', 'hermes', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);

-- ==================== 用户 ====================
INSERT INTO t_user (domain_id, openid, status, email_verified, nickname, picture, email) VALUES
('piam', 'heliannuuthus', 0, 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'heliannuuthus', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);