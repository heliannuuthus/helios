-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 服务 ====================
-- domain_id = '-' 表示跨域内置服务，属于全部域
INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', '4fervVK6unv+NAyv1meJiTUOVhdULm+FlaG+l1Uni21OAQ1v6LkKvQQFDrSuKte3TAyBcU0wI87lgeE1', 7200, 604800),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'YpbH9KNOa5mH1i3bEJWwAp5IlvkduCQ1C7l2ahqo7S7qtrbXT1JeToakS/56tEj5PsUAJSVrBzFcNwG+', 7200, 604800)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);

-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_origins) VALUES
('atlas', 'piam', 'Atlas 管理控制台', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]')
ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins);

-- ==================== 应用 IDP 配置 ====================
INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES
('atlas', 'oper', 10, 'password', 'email_otp,webauthn', 'captcha'),
('atlas', 'google', 5, NULL, NULL, NULL),
('atlas', 'github', 5, NULL, NULL, NULL)
ON DUPLICATE KEY UPDATE priority = VALUES(priority), strategy = VALUES(strategy), delegate = VALUES(delegate), `require` = VALUES(`require`);

-- ==================== 应用服务关系 ====================
INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES
('atlas', 'hermes', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);

-- ==================== 用户 ====================
INSERT INTO t_user (openid, status, username, email_verified, nickname, picture, email) VALUES
('heliannuuthus', 0, 'heliannuuthus', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username);

-- ==================== 用户身份 ====================
-- global 身份为域级对外标识（token 中的 sub），其他为认证身份
INSERT INTO t_user_identity (domain, openid, idp, t_openid) VALUES
('piam', 'heliannuuthus', 'global', 'f48f7ec5c7561f4b4f76f98d47476461'),
('piam', 'heliannuuthus', 'oper', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'heliannuuthus', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);