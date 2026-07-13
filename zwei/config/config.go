package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gorm.io/gorm"

	baseconfig "github.com/heliannuuthus/pkg/config"
	pkgdb "github.com/heliannuuthus/pkg/database"
	"github.com/heliannuuthus/pkg/logger"
)

// Cfg 返回 Zwei 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Zwei()
}

// Validate 校验 Zwei 启动所需的全部配置。
func Validate() error {
	var errs []error
	for _, key := range []string{
		"db.url", "aegis.audience", "aegis.issuer", "aegis.secret-key",
		"openrouter.api-key", "openrouter.model", "amap.api-key",
	} {
		if strings.TrimSpace(Cfg().GetString(key)) == "" {
			errs = append(errs, fmt.Errorf("必需配置 %s 未设置", key))
		}
	}
	if _, err := GetAegisSecretKeyBytes(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// GetAegisAudience 获取 Zwei 服务 audience（用于 token 验证）
func GetAegisAudience() string {
	audience := Cfg().GetString("aegis.audience")
	if audience == "" {
		return "zwei"
	}
	return audience
}

// GetAegisIssuer 获取 Aegis API/issuer 端点。
func GetAegisIssuer() string {
	issuer := strings.TrimRight(Cfg().GetString("aegis.issuer"), "/")
	if issuer == "" {
		return "https://aegis.heliannuuthus.com/api"
	}
	return issuer
}

// GetAegisSecretKeyBytes 获取 Zwei 服务的 48 字节 token seed。
func GetAegisSecretKeyBytes() ([]byte, error) {
	secret := Cfg().GetString("aegis.secret-key")
	if secret == "" {
		return nil, fmt.Errorf("zwei aegis.secret-key 未配置")
	}
	seed, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("解码 zwei aegis.secret-key 失败: %w", err)
	}
	if len(seed) != 48 {
		return nil, fmt.Errorf("zwei aegis.secret-key 长度错误: 期望 48 字节 seed, 实际 %d 字节", len(seed))
	}
	return seed, nil
}

// InitDB 初始化 Zwei 数据库连接
func InitDB() *gorm.DB {
	cfg := Cfg()
	dsn := parseDSNFromURL(cfg.GetString("db.url"))

	db, err := pkgdb.Connect(dsn)
	if err != nil {
		logger.Fatalf("连接 Zwei 数据库失败: %v", err)
	}
	logger.Infof("数据库连接成功 (zwei)")
	return db
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
