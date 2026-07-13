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
('consumer', 'wxmp'),
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
ON DUPLICATE KEY UPDATE domain_id = VALUES(domain_id);

-- ==================== 服务 ====================
INSERT INTO t_service (service_id, domain_id, name, description, logo_url, access_token_expires_in) VALUES
('hermes', '-', 'Hermes 管理服务', '身份与访问管理服务', 'https://aegis.heliannuuthus.com/logos/hermes.svg', 7200),
('iris', '-', 'Iris 用户服务', '用户信息管理服务', 'https://aegis.heliannuuthus.com/logos/iris.svg', 7200),
('zwei', 'platform', 'Zwei 菜谱服务', '菜谱管理、收藏、推荐服务', 'https://aegis.heliannuuthus.com/logos/zwei.svg', 7200),
('chaos', 'platform', 'Chaos 聚合服务', '邮件发送、文件上传等业务聚合服务', 'https://aegis.heliannuuthus.com/logos/chaos.svg', 7200)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), logo_url = VALUES(logo_url), domain_id = VALUES(domain_id);

-- ==================== 域密钥 & 服务密钥 & 应用密钥 ====================
DELETE FROM t_key WHERE owner_type IN ('domain', 'service', 'application');
INSERT INTO t_key (owner_type, owner_id, encrypted_key) VALUES
('domain', 'consumer', '/qUV7qtJPyTsgjIJv//gtwdnkqW8ahtmwUtBeQRqCbJ2ksNQoqulbf0kUvWOWaXvsULx3m0Wv2b26Ruft0o4xEyHP7Q4bF5Rz4LVpw=='),
('domain', 'platform', '9cJPfBzNt0DMP3/mJDafRfJn9mNyB7E3kTxp+bSnR2IeOaaCADg0yNBiqcYKFMYCGnU2XNj87tZqjbIelNQJhCmEBd6G0ZrGQR99jw=='),
('service', 'hermes', '1S1waa2ygh6piKQk0Ysu14LBBZQHhuavHrWd+HaLgT9UVIipws68rakC5Uu3waorjDHUhX3+hSm783nTBa2zjLs98n8yXQSkGAb3Hg=='),
('service', 'iris', 'gyEqmXslnZGGNC2qTcd8YeEWVzXp64AxNF2wMuIXk2IVtnuYJE6d8jRacb9Dqq4uohf7OGa7J/a11/vx2quFti7sNS4JDMRcDwicBQ=='),
('service', 'zwei', 'yP27/ndt+uIe3V5cq3a6RKHT0WhWC50pK/APR+TGmg6ln5iNRyHvS6K57gItW5F5u8ZVCJK6+sMfez7tiqkFGrERG0gM6IfRqy9hiw=='),
('service', 'chaos', '2ur57JRt5zHHeMgp8+O/bsSKvZK4YuA3PjVzsUGFsIphb0l7RkNOUCRf1F4d9Qa/HeLJyHsND3mGp8fdBcrvRJX5x7SS79sCKPiIaQ=='),
('application', 'atlas', 'HdAbuQK3SyGKcERKGu4j0w4+CLkb4vTHAJ+xkFFtCU6JFVrzSIVRbL3SsKk0ZajLaFAH5cyYJBjtffeB3QAo8wD8+wE6kik/F3nMyg=='),
('application', 'zwei', 'm+sUWSINKr2TI73Y58KffcrpDE2NYTxhEeDpxXmpgLqD+hCi83PSPspH7lEu8Lk6xJAmArSbTvFZL3CeqTEKyCgwvpXBBs+5JyGFQw=='),
('application', 'hermes', 'SCp5qMYqlEpKURngeZonjmdMJExsrAJt64gKf6iesBDx3C7BF/2gji5Ig86AyebpjMHm6HZvRrplifHuKZ6F0pPxSUALj2sxOyNMNA=='),
('application', 'chaos', 'vNOkwfF4zeOxQ/uTDxhAcRb53fyF0sHif4M0YrA/udjBpzQVaOoJVSWVP9/YH9cE03E6L01uCxXy9+C8snp0hF9z56SHVtOix7wKvQ=='),
('application', 'piris', 'QDrGb7ll/0yGKb7wSPzzyWNfaLr5xetPDxc0nACKUHirnXWKd5Se1oIkMuxv9OJeL4LxA4+3mI3WYqZUw+o4WFxq65R8tzlcZ2e2fA=='),
('application', 'ciris', 'ZwgGfkyINYhufcN08wdTeERoAgZUoCGJSQZp6031q3AooQXTD6TSxKmiNkbd9k0slZt4XUYt9DhLIEBxACB9QwXR9df6431G7WVzHQ==')
;

-- ==================== 第三方 IDP 密钥（AES-256-GCM 密文） ====================
INSERT INTO t_idp_key (idp_type, t_app_id, t_secret) VALUES
('github', 0x4f7632336c696d52713450717077364472624775, 0x7141643135494b59774754537a322f46494b486b77544437534f7a6d6973742b5364544a636132785469796b44332b74662f74304e414e3539547162594f61314747312f6a5179673979427a414a73634638704d70745676454f593d),
('google', 0x34353131363631323532352d36626466766e35677139766a70657039736275637476646931636a32623467322e617070732e676f6f676c6575736572636f6e74656e742e636f6d, 0x383049316567636a2f674e7a5569756d4a686f734f617678664446585037564b673774796e4966724846526f775047397964736e4c662b74696e6d484f5a5554725a48743545754c685867707550666465364571),
('wxmp', 0x777834653665616563303130663236393634, 0x50654e3174634444583237356e484f66722b3138534f376137656236574a724c7461326f75437070784341794a45315554736d796e77636243717737664a3478464c53764a6b6b6e484c547466704d53),
('ttmp', 0x7474616536656438643333303064333532353031, 0x7a572f69537168595835786e704d384c435a625045744f31707249754173787a33433746324270456c7055655376764b6a79504b59522f524331422f6349364e6b32567a727536536d3550495779442b3736644c77614c583679513d),
('almp', 0x32303231303036313236363334333438, 0x642f6d634159757165464968566e6a64627033316c4a586573523777527a4539704c414e545177464c6535384a4e3154347256484d7a316c36592b2b34644e7670794b336f39766d3452784736735173524d39666f706738434c396d6e667a5259356d6a6e6545474870324639742b364730636438625a3669564c5374334166574165787756562f6d56654a56395541434a2f7055324361436f315572744e656b5a644134446e726d365656657a57614f5869412f53794e4b30714d784959454647544352322f3951356b65646b486e786f6f796e6662676f734161397357754d74424e556847485954634b4c7759742f4f2b6e3039314a4d2b724949594c542b4c5164564f59755930775a6b3552576b504450314d75687345756a4e334731314c595467477432487849796d4e77636d54464735775741316e786846644751473373584e64535975527877706e4532306f44366731763246796f2b67576b65554e5a454958742f75624441386553394e666137586f43347150513055753553695541455a644469335674716a56534b5262317956645a5174464f30703567514f534735587566655779394f756b5367507251442b67614c6265535a2f49684f663132524b424278427569676c453971794f7052384334646f6c474d666752797271736f2b3449656a50735444324a5a515a514254794a524d51425146334d464a2f692f56564b7a4448795a4e6566546f305066584b5676546c4f38694b5342716136496c7377382b2b4e58595a71394a7056616949462b47597852684b63394a514c6471454a5870626638684638527937583257756d6c54707741677a44444538566b733330747337763955357059653366796c4573726341306f7a394151506449396e655637304b7a45516c2f6e446750397248316a6f306b38434731656466305263726a366f5654306a4d716277306e6a546a4c6d596e492f595439494d2b7134346868704c666c6f5450354b627367356653576b69494c6e6f4b6a454964526261706743776b2f693733504c5a64626436656770505a727a5267794c4547345343776f7a754f4953687a754443563130644d33435163416538356c787567444768796c5364724e63396c5461493967716c76374a7a314b79473873486b575a4a6c453850523133647133586d37777969766d4f395178734a7139687a586c6438376667466667766e7667794d374f6e4d695a5732614e787645464b594a7957545538433376424c734a30415649383959644c3159536c334d527457384e6c792f346d5a376b744742452b66725433356f4d594e434e557864704976416b535a7a2f3845493437634c6a645936626d4f326e766933686c6571616b71304853433635514859334c6d4a79705436526f7563674763364b45416e63315a727274515a434349776e636c33486268674348496b56396132573447485935774f4754566f43374664414e7574324774417a53537970366f50416c74583169564f4a626f3752494a576a354d3031727566372f74416d425534377461596737486e435775364d57547756454167692f5330686e56374243532b4b45655836623272362b6d73524936685948536d674c4d6d5a644c70747875714548573055586f694d745456503563326d4f794e6c617134435a31517a4b55764c597779556973334772306857454237327855766642346747486762754e73556b7349706d67466e2f316e346a72424d745847687a42314b5731516f62615932376e3059716e567a2b5743485976484e68366e4231747839694d62545971585570543778503478346b5374684768444e474f34486279476a6961544b2f6b574b45376a6d57724478654f5a622f79696a4a7a7231493762335166794670326a2b7333484b4942434842545375516b703664324668427551445344426e54355358585764526c437165412b6d4a676e336b79365561775a533770626d476c506b64766f686e66624a6f764455464f58534867735231306c4e33593877307034464f613130635775744355744830623442646c53784d7841714c6f77305757705a4d46537749677432636f2b48624358355936396770684445385038416d547a6a7462426d4f69566f6e5845334c45664d535251564441377450496a6c41435a31794876484935434c516672694e6137494b6b4a64755463642b62634c5248515933367438656f707a7252652b56416c41544e2f75744e63435a676e4f676f395346756d346b565179766d58453158344b7a6f345236585a612b65386c64336f4644446763464277417857706769456c696943516d79714e554450566e6742786b617037445669726d364d614c507a7945666439692f7534446a45586b466b594b5a6c4e676a6d55586636745541455134354879303073416d52645a66726d51434134637351757844446a452f38364d6464454336506435534c63724c4955556256755669687377544f456c36573072326347595935462f47344341584a56444c53526a43725a426f6b34364250755566546b584b344854794f2f677841496a3263486a52394c427557374d6f747576706d44715271304d4d326155666e745542425277557166417771384d3779506e476e7175757467386b50446d5a3730384d79787855744d6272412f324e5a6e39644f4d6c5066615779703141716a3653755257387751476169556e7432574a49625a3866742f2b3149512f4b2b522b52574a62514650566f54675367502b716a4e39336c53554e486e413776527167492b476a57584272613958303252524f68474358596e30715851394775514445626a69397449525278346b7a48417675733148564a3255546e432f582f6a6c474f6c627571696b545954324d4d38482f70686e6a682f344873795a36497162665079647764424b373765766156576b5a49673277454f502f3337792f4474793076714a56434c706873524169646b396a5167303449346934677169624f7138396135674658766f6f736b586e33324e6c72467a6a6a336d5130396757792b38555234762f70513d)
ON DUPLICATE KEY UPDATE t_secret = VALUES(t_secret);

-- ==================== 域 IDP 默认配置 ====================
INSERT INTO t_domain_idp_config (domain_id, idp_type, priority, t_app_id) VALUES
('platform', 'github', 5, 0x4f7632336c696d52713450717077364472624775),
('platform', 'google', 5, 0x34353131363631323532352d36626466766e35677139766a70657039736275637476646931636a32623467322e617070732e676f6f676c6575736572636f6e74656e742e636f6d),
('consumer', 'wxmp', 5, 0x777834653665616563303130663236393634),
('consumer', 'ttmp', 5, 0x7474616536656438643333303064333532353031),
('consumer', 'almp', 5, 0x32303231303036313236363334333438)
ON DUPLICATE KEY UPDATE priority = VALUES(priority), t_app_id = VALUES(t_app_id);


-- ==================== 应用 ====================
INSERT INTO t_application (app_id, domain_id, name, description, logo_url, redirect_uris, allowed_origins, allowed_logout_uris, id_token_expires_in, refresh_token_expires_in, refresh_token_absolute_expires_in) VALUES
('atlas', 'platform', 'Atlas 管理控制台', 'Hermes 身份与访问管理系统的官方管理后台，支持域、应用、服务及关系的配置与可视化管理。', 'https://aegis.heliannuuthus.com/logos/atlas.svg', '["https://atlas.heliannuuthus.com/auth/callback"]', '["https://atlas.heliannuuthus.com"]', NULL, 3600, 604800, 0),
('zwei', 'platform', 'Zwei 菜谱管理', '企业级菜谱管理与分发系统，集成 Hermes 实现细粒度的权限控制。', NULL, '["https://zwei.heliannuuthus.com/auth/callback"]', '["https://zwei.heliannuuthus.com"]', NULL, 3600, 604800, 0),
('hermes', 'platform', 'Hermes 身份管理', '身份验证与授权中心，提供 OIDC/OAuth2 协议支持与 ReBAC 鉴权能力。', NULL, '["https://hermes.heliannuuthus.com/auth/callback"]', '["https://hermes.heliannuuthus.com"]', NULL, 3600, 604800, 0),
('chaos', 'platform', 'Chaos 聚合服务', '业务支撑聚合系统，包含邮件、短信、文件存储等通用能力模块。', NULL, '["https://chaos.heliannuuthus.com/auth/callback"]', '["https://chaos.heliannuuthus.com"]', NULL, 3600, 604800, 0),
('piris', 'platform', '平台个人中心', 'B 端员工个人信息管理与安全设置中心。', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]', NULL, 3600, 604800, 0),
('ciris', 'consumer', '用户个人中心', 'C 端外部用户个人账号管理与偏好设置中心。', NULL, '["https://iris.heliannuuthus.com/auth/callback"]', '["https://iris.heliannuuthus.com"]', NULL, 3600, 604800, 0)
ON DUPLICATE KEY UPDATE name = VALUES(name), description = VALUES(description), logo_url = VALUES(logo_url), redirect_uris = VALUES(redirect_uris), allowed_origins = VALUES(allowed_origins), allowed_logout_uris = VALUES(allowed_logout_uris), id_token_expires_in = VALUES(id_token_expires_in), refresh_token_expires_in = VALUES(refresh_token_expires_in), refresh_token_absolute_expires_in = VALUES(refresh_token_absolute_expires_in);

-- ==================== 应用 IDP 配置 ====================
INSERT INTO t_application_idp_config (app_id, `type`, priority, strategy, delegate, `require`) VALUES
('atlas', 'staff', 10, 'password', 'email-code,webauthn', 'captcha'),
('atlas', 'google', 5, NULL, NULL, NULL),
('atlas', 'github', 5, NULL, NULL, NULL),
('zwei', 'staff', 10, 'password', 'email-code,webauthn', 'captcha'),
('zwei', 'google', 5, NULL, NULL, NULL),
('zwei', 'github', 5, NULL, NULL, NULL),
('hermes', 'staff', 10, 'password', 'email-code,webauthn', 'captcha'),
('hermes', 'google', 5, NULL, NULL, NULL),
('hermes', 'github', 5, NULL, NULL, NULL),
('chaos', 'staff', 10, 'password', 'email-code,webauthn', 'captcha'),
('chaos', 'google', 5, NULL, NULL, NULL),
('chaos', 'github', 5, NULL, NULL, NULL),
('piris', 'staff', 10, 'password', 'email-code,webauthn', 'captcha'),
('piris', 'google', 5, NULL, NULL, NULL),
('piris', 'github', 5, NULL, NULL, NULL),
('ciris', 'user', 10, 'password', 'sms-code', NULL),
('ciris', 'wxmp', 5, NULL, NULL, NULL),
('ciris', 'wechat', 5, NULL, NULL, NULL)
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
('iris', 'user:verify', 300, '{"1m": 1, "24h": 10}')
ON DUPLICATE KEY UPDATE expires_in = VALUES(expires_in), limits = VALUES(limits);

-- ==================== 用户 ====================
INSERT INTO t_user (openid, status, username, password_hash, email_verified, nickname, picture, email) VALUES
('11ffa2fb5bfa3b8f8e805d88c479f306', 0, 'heliannuuthus', '$2b$12$SKdQyt5r5/U2IQV/UUVOxOLc80ZSEwpWlvfQ7zDTby0fwN5jbGe6y', 1, 'Heliannuuthus', NULL, 'heliannuuthus@gmail.com')
ON DUPLICATE KEY UPDATE nickname = VALUES(nickname), email = VALUES(email), email_verified = VALUES(email_verified), username = VALUES(username), password_hash = VALUES(password_hash);

-- ==================== 用户身份 ====================
INSERT INTO t_user_identity (domain, uid, idp, t_openid) VALUES
('platform', '11ffa2fb5bfa3b8f8e805d88c479f306', 'global', '11ffa2fb5bfa3b8f8e805d88c479f306'),
('platform', '11ffa2fb5bfa3b8f8e805d88c479f306', 'staff', 'heliannuuthus')
ON DUPLICATE KEY UPDATE t_openid = VALUES(t_openid);

-- ==================== 服务关系（权限） ====================
INSERT INTO t_relationship (service_id, subject_type, subject_id, relation, object_type, object_id) VALUES
('hermes', 'user', '11ffa2fb5bfa3b8f8e805d88c479f306', 'admin', '*', '*')
ON DUPLICATE KEY UPDATE relation = VALUES(relation);
