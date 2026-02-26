package config

import (
	"fmt"
	"net/url"
	"strings"

	"gorm.io/gorm"

	baseconfig "github.com/heliannuuthus/helios/pkg/config"
	pkgdb "github.com/heliannuuthus/helios/pkg/database"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Cfg 返回 Zwei 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Zwei()
}

// parseDSNFromURL 将 mysql://user:pass@host:port/db?params 格式转换为 Go MySQL DSN 格式
func parseDSNFromURL(dbURL string) string {
	if !strings.HasPrefix(dbURL, "mysql://") {
		return dbURL
	}
	u, err := url.Parse(dbURL)
	if err != nil {
		logger.Fatalf("解析数据库 URL 失败: %v", err)
	}
	user := u.User.Username()
	password, _ := u.User.Password()
	host := u.Host
	database := strings.TrimPrefix(u.Path, "/")
	query := u.RawQuery
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", user, password, host, database)
	if query != "" {
		dsn += "?" + query
	}
	return dsn
}

// InitDB 初始化 Zwei 数据库连接
func InitDB() *gorm.DB {
	cfg := Cfg()
	dsn := parseDSNFromURL(cfg.GetString("db.url"))

	db, err := pkgdb.Connect(dsn)
	if err != nil {
		logger.Fatalf("连接 Zwei 数据库失败: %v", err)
	}
	logger.Infof("数据库连接成功 (zwei): %s", dsn)
	return db
}
