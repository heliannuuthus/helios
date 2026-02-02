-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 服务 ====================
-- domain_id = '-' 表示跨域内置服务，属于全部域
INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', 'HawIx3yfeIU5hkWPqM/dhiVJ682FB4/brPszu10g+URIIrd0V5d9UigiWEOK7groZJslch6bSYOi1ddl', 7200, 604800),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'EQC2OsWg80zU1WcpXAjHmlTtT/OsYh+Qwf4C5JgNxuG2c07YTxpE+c1hXlYacno34+M71jRlKCkdTD6Z', 7200, 604800)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), encrypted_key = VALUES(encrypted_key), domain_id = VALUES(domain_id);

-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, logo_url, redirect_uris, allowed_idps, allowed_origins) VALUES
('atlas', 'piam', 'Atlas 管理控制台', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["email", "google", "github"]', '["https://atlas.heliannuuthus.com"]')
ON DUPLICATE KEY UPDATE name = VALUES(name), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_idps = VALUES(allowed_idps), allowed_origins = VALUES(allowed_origins);

-- ==================== 应用服务关系 ====================
INSERT INTO t_application_service_relation (app_id, service_id, relation) VALUES
('atlas', 'hermes', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);

-- ==================== 用户 ====================
INSERT INTO t_user (openid, domain_id, status, email_verified, nickname, picture, email) VALUES
('heliannuuthus', 'piam', 0, 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'heliannuuthus', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);