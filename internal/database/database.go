package database

import (
	"fmt"
	"net/url"
	"strings"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/config"
	pkgdb "github.com/heliannuuthus/helios/pkg/database"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	zweiDB   *gorm.DB // Zwei 数据源（业务数据）
	hermesDB *gorm.DB // Hermes 数据源（身份与访问管理数据）
)

// parseDSNFromURL 将 mysql://user:pass@host:port/db?params 格式转换为 Go MySQL DSN 格式
// 输入: mysql://helios:helios@localhost:3306/hermes?charset=utf8mb4&parseTime=true
// 输出: helios:helios@tcp(localhost:3306)/hermes?charset=utf8mb4&parseTime=true
func parseDSNFromURL(dbURL string) string {
	// 如果已经是 DSN 格式（不含 mysql://），直接返回
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

// buildOptions 从配置构建连接池选项
func buildOptions(cfg *config.Cfg, maxIdleKey, maxOpenKey, maxLifetimeKey, maxIdleTimeKey, slowThresholdKey string) []pkgdb.Option {
	var opts []pkgdb.Option

	opts = append(opts, pkgdb.WithLogWriter(logger.GormWriter()))

	if maxIdleConns := cfg.GetInt(maxIdleKey); maxIdleConns > 0 {
		opts = append(opts, pkgdb.WithMaxIdleConns(maxIdleConns))
	}
	if maxOpenConns := cfg.GetInt(maxOpenKey); maxOpenConns > 0 {
		opts = append(opts, pkgdb.WithMaxOpenConns(maxOpenConns))
	}
	if connMaxLifetime := cfg.GetDuration(maxLifetimeKey); connMaxLifetime > 0 {
		opts = append(opts, pkgdb.WithConnMaxLifetime(connMaxLifetime))
	}
	if connMaxIdleTime := cfg.GetDuration(maxIdleTimeKey); connMaxIdleTime > 0 {
		opts = append(opts, pkgdb.WithConnMaxIdleTime(connMaxIdleTime))
	}
	if slowThreshold := cfg.GetDuration(slowThresholdKey); slowThreshold > 0 {
		opts = append(opts, pkgdb.WithSlowThreshold(slowThreshold))
	}

	return opts
}

// Init 初始化所有数据库连接
func Init() {
	InitZwei()
	InitHermes()
}

// InitZwei 初始化 Zwei 数据源（业务数据）
func InitZwei() *gorm.DB {
	if zweiDB != nil {
		return zweiDB
	}

	cfg := config.Zwei()
	dsn := parseDSNFromURL(cfg.GetString(config.DBURL))
	var err error
	zweiDB, err = pkgdb.Connect(dsn)
	if err != nil {
		logger.Fatalf("连接 Zwei 数据库失败: %v", err)
	}

	logger.Infof("数据库连接成功 (zwei): %s", dsn)
	return zweiDB
}

// InitHermes 初始化 Hermes 数据源（身份与访问管理数据）
func InitHermes() *gorm.DB {
	if hermesDB != nil {
		return hermesDB
	}

	cfg := config.Hermes()
	dsn := parseDSNFromURL(cfg.GetString(config.DBURL))
	opts := buildOptions(cfg,
		config.DBPoolMaxIdleConns,
		config.DBPoolMaxOpenConns,
		config.DBPoolConnMaxLifetime,
		config.DBPoolConnMaxIdleTime,
		config.DBSlowThreshold,
	)

	var err error
	hermesDB, err = pkgdb.Connect(dsn, opts...)
	if err != nil {
		logger.Fatalf("连接 Hermes 数据库失败: %v", err)
	}

	logger.Infof("数据库连接成功 (hermes): %s", cfg.GetString(config.DBURL))
	return hermesDB
}

// GetZwei 获取 Zwei 数据库连接
func GetZwei() *gorm.DB {
	if zweiDB == nil {
		return InitZwei()
	}
	return zweiDB
}

// GetHermes 获取 Hermes 数据库连接
func GetHermes() *gorm.DB {
	if hermesDB == nil {
		return InitHermes()
	}
	return hermesDB
}

// GetAuth 获取 Auth 数据库连接（兼容旧代码，返回 Hermes 数据源）
// Deprecated: 请使用 GetHermes()
func GetAuth() *gorm.DB {
	return GetHermes()
}
