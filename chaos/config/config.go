package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"gorm.io/gorm"

	baseconfig "github.com/heliannuuthus/pkg/config"
	pkgdb "github.com/heliannuuthus/pkg/database"
	"github.com/heliannuuthus/pkg/logger"
)

var (
	chaosDB     *gorm.DB
	chaosDBOnce sync.Once
)

// Cfg 返回 Chaos 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Chaos()
}

// GetAegisAudience 获取 Chaos 服务 audience（用于 token 验证）
func GetAegisAudience() string {
	audience := Cfg().GetString("aegis.audience")
	if audience == "" {
		return "chaos"
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

// GetAegisSecretKeyBytes 获取 Chaos 服务的 48 字节 token seed。
func GetAegisSecretKeyBytes() ([]byte, error) {
	secret := Cfg().GetString("aegis.secret-key")
	if secret == "" {
		return nil, fmt.Errorf("chaos aegis.secret-key 未配置")
	}
	seed, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("解码 chaos aegis.secret-key 失败: %w", err)
	}
	if len(seed) != 48 {
		return nil, fmt.Errorf("chaos aegis.secret-key 长度错误: 期望 48 字节 seed, 实际 %d 字节", len(seed))
	}
	return seed, nil
}

// GetSMTPHost 获取 SMTP 主机
func GetSMTPHost() string {
	return Cfg().GetString("smtp.host")
}

// GetSMTPPort 获取 SMTP 端口
func GetSMTPPort() int {
	port := Cfg().GetInt("smtp.port")
	if port == 0 {
		return 587
	}
	return port
}

// GetSMTPUsername 获取 SMTP 用户名
func GetSMTPUsername() string {
	return Cfg().GetString("smtp.username")
}

// GetSMTPPassword 获取 SMTP 密码
func GetSMTPPassword() string {
	return Cfg().GetString("smtp.password")
}

// GetSMTPFrom 获取发件人地址
func GetSMTPFrom() string {
	return Cfg().GetString("smtp.from")
}

// GetSMTPFromName 获取发件人名称
func GetSMTPFromName() string {
	name := Cfg().GetString("smtp.from-name")
	if name == "" {
		return "Helios"
	}
	return name
}

// GetCloudflareR2AccessKeyID 获取 R2 Access Key ID
func GetCloudflareR2AccessKeyID() string {
	return Cfg().GetString("r2.access-key-id")
}

// GetCloudflareR2AccessKeySecret 获取 R2 Access Key Secret
func GetCloudflareR2AccessKeySecret() string {
	return Cfg().GetString("r2.access-key-secret")
}

// GetCloudflareR2Bucket 获取 R2 Bucket 名称
func GetCloudflareR2Bucket() string {
	return Cfg().GetString("r2.bucket")
}

// GetCloudflareR2Endpoint 获取 R2 Endpoint（根据 Account ID 构建）
func GetCloudflareR2Endpoint() string {
	accountID := Cfg().GetString("r2.account-id")
	if accountID == "" {
		return ""
	}
	return "https://" + accountID + ".r2.cloudflarestorage.com"
}

// GetCloudflareR2PublicURL 获取 R2 公开访问 URL
func GetCloudflareR2PublicURL() string {
	return Cfg().GetString("r2.domain")
}

// InitDB 初始化 Chaos 数据库连接（单例）
func InitDB() *gorm.DB {
	chaosDBOnce.Do(func() {
		cfg := Cfg()
		dsn := parseDSNFromURL(cfg.GetString("db.url"))

		db, err := pkgdb.Connect(dsn, pkgdb.WithLogWriter(logger.GormWriter()))
		if err != nil {
			logger.Fatalf("连接 Chaos 数据库失败: %v", err)
		}
		logger.Infof("数据库连接成功 (chaos)")
		chaosDB = db
	})
	return chaosDB
}

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
