-- 为用户凭证增加展示名称；创建时由后端推断，之后允许用户重命名
ALTER TABLE t_user_credential
ADD COLUMN label VARCHAR(128) NOT NULL DEFAULT '' COMMENT '凭证名称，创建时推断，用户可重命名' AFTER credential_id;

UPDATE t_user_credential
SET label = CASE
  WHEN `type` = 'totp' THEN '身份验证器 App'
  WHEN `type` = 'passkey' THEN '通行密钥'
  WHEN `type` = 'webauthn' THEN '通行密钥'
  ELSE '安全凭证'
END
WHERE label = '';
