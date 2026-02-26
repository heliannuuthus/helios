package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"gorm.io/gorm"

	baseconfig "github.com/heliannuuthus/helios/pkg/config"
	pkgdb "github.com/heliannuuthus/helios/pkg/database"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Cfg 返回 Hermes 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Hermes()
}

// ==================== 数据库 ====================

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

// InitDB 初始化 Hermes 数据库连接
func InitDB() *gorm.DB {
	cfg := Cfg()
	dsn := parseDSNFromURL(cfg.GetString("db.url"))

	var opts []pkgdb.Option
	opts = append(opts, pkgdb.WithLogWriter(logger.GormWriter()))
	if v := cfg.GetInt("db.pool.max-idle-conns"); v > 0 {
		opts = append(opts, pkgdb.WithMaxIdleConns(v))
	}
	if v := cfg.GetInt("db.pool.max-open-conns"); v > 0 {
		opts = append(opts, pkgdb.WithMaxOpenConns(v))
	}
	if v := cfg.GetDuration("db.pool.conn-max-lifetime"); v > 0 {
		opts = append(opts, pkgdb.WithConnMaxLifetime(v))
	}
	if v := cfg.GetDuration("db.pool.conn-max-idle-time"); v > 0 {
		opts = append(opts, pkgdb.WithConnMaxIdleTime(v))
	}
	if v := cfg.GetDuration("db.slow-threshold"); v > 0 {
		opts = append(opts, pkgdb.WithSlowThreshold(v))
	}

	db, err := pkgdb.Connect(dsn, opts...)
	if err != nil {
		logger.Fatalf("连接 Hermes 数据库失败: %v", err)
	}
	logger.Infof("数据库连接成功 (hermes): %s", cfg.GetString("db.url"))
	return db
}

// ==================== 域签名密钥 ====================

// GetDomainSignKeys 获取域签名密钥列表（原始字符串，逗号分隔）
func GetDomainSignKeys(domainID string) []string {
	keyStr := Cfg().GetString("aegis.domains." + domainID + ".sign-keys")
	if keyStr == "" {
		return nil
	}
	return strings.Split(keyStr, ",")
}

// GetDomainSignKeysBytes 获取域签名密钥列表（解码后的 32 字节 Ed25519 seed）
func GetDomainSignKeysBytes(domainID string) ([][]byte, error) {
	keyStrs := GetDomainSignKeys(domainID)
	if len(keyStrs) == 0 {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}
	keys := make([][]byte, 0, len(keyStrs))
	for i, keyStr := range keyStrs {
		keyStr = strings.TrimSpace(keyStr)
		if keyStr == "" {
			continue
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("解码签名密钥[%d]失败: %w", i, err)
		}
		keys = append(keys, keyBytes)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}
	return keys, nil
}

// ==================== Aegis 集成配置 ====================

// GetAegisAudience 获取 Hermes 服务 audience（用于 token 验证）
func GetAegisAudience() string {
	audience := Cfg().GetString("aegis.audience")
	if audience == "" {
		return "hermes"
	}
	return audience
}

// GetAegisSecretKey 获取 Hermes 服务解密密钥（原始字符串）
func GetAegisSecretKey() string {
	return Cfg().GetString("aegis.secret-key")
}

// GetAegisSecretKeyBytes 获取 Hermes 服务解密密钥（32 字节 raw key）
func GetAegisSecretKeyBytes() ([]byte, error) {
	secretStr := GetAegisSecretKey()
	if secretStr == "" {
		return nil, fmt.Errorf("hermes aegis.secret-key 未配置")
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 hermes aegis.secret-key 失败: %w", err)
	}
	if len(secretBytes) != 32 {
		return nil, fmt.Errorf("hermes aegis.secret-key 长度错误: 期望 32 字节, 实际 %d 字节", len(secretBytes))
	}
	return secretBytes, nil
}

// ==================== 数据库加密 ====================

// GetDBEncKeyRaw 获取数据库加密密钥的原始字节
func GetDBEncKeyRaw() ([]byte, error) {
	keyStr := Cfg().GetString("db.enc-key")
	if keyStr == "" {
		return nil, fmt.Errorf("db.enc-key 未配置")
	}
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("解码数据库加密密钥失败: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("数据库加密密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}
	return key, nil
}
