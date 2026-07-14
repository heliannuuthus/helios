-- 支持服务按域进行游标分页，避免 domain_id 条件退化为全表扫描。
ALTER TABLE t_service
ADD INDEX idx_service_domain_cursor (domain_id, _id);

-- 回滚：ALTER TABLE t_service DROP INDEX idx_service_domain_cursor;
