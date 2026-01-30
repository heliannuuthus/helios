package database

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/config"
	pkgdb "github.com/heliannuuthus/helios/pkg/database"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	zweiDB   *gorm.DB // Zwei 数据源（业务数据）
	hermesDB *gorm.DB // Hermes 数据源（身份与访问管理数据）
)

// buildDSN 从配置构建 MySQL DSN
func buildDSN(cfg *config.Cfg, hostKey, portKey, userKey, passwordKey, nameKey, timeoutConnectKey, timeoutReadKey, timeoutWriteKey string) string {
	host := cfg.GetString(hostKey)
	if host == "" {
		host = "localhost"
	}
	port := cfg.GetInt(portKey)
	if port == 0 {
		port = 3306
	}
	user := cfg.GetString(userKey)
	if user == "" {
		user = "root"
	}
	password := cfg.GetString(passwordKey)
	database := cfg.GetString(nameKey)

	// 超时配置
	connectTimeout := cfg.GetDuration(timeoutConnectKey)
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}
	readTimeout := cfg.GetDuration(timeoutReadKey)
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := cfg.GetDuration(timeoutWriteKey)
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=%s&readTimeout=%s&writeTimeout=%s",
		user, password, host, port, database,
		connectTimeout.String(), readTimeout.String(), writeTimeout.String())
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
	dsn := buildDSN(cfg,
		config.ZweiDBHost,
		config.ZweiDBPort,
		config.ZweiDBUser,
		config.ZweiDBPassword,
		config.ZweiDBName,
		config.ZweiDBTimeoutConnect,
		config.ZweiDBTimeoutRead,
		config.ZweiDBTimeoutWrite,
	)
	opts := buildOptions(cfg,
		config.ZweiDBPoolMaxIdleConns,
		config.ZweiDBPoolMaxOpenConns,
		config.ZweiDBPoolConnMaxLifetime,
		config.ZweiDBPoolConnMaxIdleTime,
		"database.slow-threshold",
	)
	var err error
	zweiDB, err = pkgdb.Connect(dsn, opts...)
	if err != nil {
		logger.Fatalf("连接 Zwei 数据库失败: %v", err)
	}

	logger.Infof("数据库连接成功 (zwei): %s@%s:%d/%s",
		cfg.GetString(config.ZweiDBUser),
		cfg.GetString(config.ZweiDBHost),
		cfg.GetInt(config.ZweiDBPort),
		cfg.GetString(config.ZweiDBName))
	return zweiDB
}

// InitHermes 初始化 Hermes 数据源（身份与访问管理数据）
func InitHermes() *gorm.DB {
	if hermesDB != nil {
		return hermesDB
	}

	cfg := config.Hermes()
	dsn := buildDSN(cfg,
		config.HermesDBHost,
		config.HermesDBPort,
		config.HermesDBUser,
		config.HermesDBPassword,
		config.HermesDBName,
		config.HermesDBTimeoutConnect,
		config.HermesDBTimeoutRead,
		config.HermesDBTimeoutWrite,
	)
	opts := buildOptions(cfg,
		config.HermesDBPoolMaxIdleConns,
		config.HermesDBPoolMaxOpenConns,
		config.HermesDBPoolConnMaxLifetime,
		config.HermesDBPoolConnMaxIdleTime,
		"database.slow-threshold",
	)

	var err error
	hermesDB, err = pkgdb.Connect(dsn, opts...)
	if err != nil {
		logger.Fatalf("连接 Hermes 数据库失败: %v", err)
	}

	logger.Infof("数据库连接成功 (hermes): %s@%s:%d/%s",
		cfg.GetString(config.HermesDBUser),
		cfg.GetString(config.HermesDBHost),
		cfg.GetInt(config.HermesDBPort),
		cfg.GetString(config.HermesDBName))
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
