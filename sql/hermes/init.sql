-- Hermes 初始化数据
-- 由 scripts/initialize-hermes.py 生成

USE `hermes`;

-- ==================== 服务 ====================
INSERT INTO t_service (service_id, domain_id, name, description, encrypted_key, access_token_expires_in, refresh_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', '8dx5pTbaahQWx4jErH/u3mU8BmXzAjCIV2pQa6d4UoFH8YQFYNusoEouddTkdHXkqRouCLRCYmQc/sBNAD0HQUUSBWMa+ADceDetWQ==', 7200, 604800),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'xzkXgeK6F21GTIfh3QIt/+koi2nO++PHUxjGe8UA/B1OT70yVABRZLjhw268T6nMpGRuOwn9V6qYis/f4GgwR91CwIBGuMsZYu11hg==', 7200, 604800),
('zwei', '-', 'Zwei 菜谱服务', '菜谱管理、收藏、推荐服务', 'YDcU1L65DQ0A5brqGxW0NwbGB0M84KP8yrXsFLl9S6UUy67Igda45NzzhtLK0PCjcBd6y7K4XlOZfoXXSB1f6/sO4kEBWY1442PlSA==', 7200, 604800),
('chaos', '-', 'Chaos 聚合服务', '邮件发送、文件上传等业务聚合服务', 'pBgWfoon4LF//5I8n4U2y6FAdNnxIZQSxhyPuBX3LPi5PnL/CWFW+0PbdkgmOpZ7Tq/KntGbAknsbFPYRMgge8XRRc2oPToOCNkK8w==', 7200, 604800)
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
('atlas', 'zwei', '*'),
('atlas', 'chaos', '*'),
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
('heliannuuthus', 0, 'heliannuuthus', '$2b$10$QBdKVhHH5g5kJAGAzhYgOu4Vb3i10rRAGuoJ.hxkhhov5AGaLLwN6', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO t_user_identity (domain, openid, idp, t_openid) VALUES
('platform', 'heliannuuthus', 'global', 'df406fed3530ef8eb0bd9b7609b928f2'),
('platform', 'heliannuuthus', 'staff', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', 'heliannuuthus', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);