-- Chaos 数据库 Schema（运维/模板/邮件）
-- MySQL 语法

CREATE DATABASE IF NOT EXISTS `chaos` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

GRANT ALL PRIVILEGES ON `chaos`.* TO 'helios'@'%';
FLUSH PRIVILEGES;

USE `chaos`;
