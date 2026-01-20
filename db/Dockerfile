FROM mysql:8.0

# 复制自定义 MySQL 配置文件
COPY my.cnf /etc/mysql/conf.d/custom.cnf

# MySQL 官方镜像会在首次启动时自动执行 /docker-entrypoint-initdb.d/ 目录下的文件
# 文件会按字母顺序执行：.sh -> .sql -> .sql.gz
# SQL 文件中已包含 CREATE DATABASE 和 USE 语句，无需 shell 脚本

# 复制 schema 文件（按文件名顺序执行）
COPY auth/schema.sql /docker-entrypoint-initdb.d/01-auth-schema.sql
COPY auth/init.sql /docker-entrypoint-initdb.d/02-auth-init.sql
COPY zwei/schema.sql /docker-entrypoint-initdb.d/03-zwei-schema.sql
COPY zwei/init.sql /docker-entrypoint-initdb.d/04-zwei-init.sql

# 暴露端口
EXPOSE 3306

# MySQL 默认启动命令
CMD ["mysqld"]
