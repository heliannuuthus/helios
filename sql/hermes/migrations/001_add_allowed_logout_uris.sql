-- 添加登出后允许跳转的 URI 列（已有列则跳过）
ALTER TABLE t_application
ADD COLUMN allowed_logout_uris VARCHAR(1024) DEFAULT NULL COMMENT '登出后允许跳转的 URI（JSON 数组）' AFTER allowed_origins;
