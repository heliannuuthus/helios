package config

import (
	baseconfig "github.com/heliannuuthus/helios/pkg/config"
)

// Cfg 返回 Chaos 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Chaos()
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

// GetCloudflareAccountID 获取 Cloudflare Account ID（复用主配置）
func GetCloudflareAccountID() string {
	return baseconfig.GetR2AccountID()
}

// GetCloudflareAPIToken 获取 Cloudflare API Token（即 R2 Access Key ID）
func GetCloudflareAPIToken() string {
	return baseconfig.GetR2AccessKeySecret()
}

// GetCloudflareR2AccessKeyID 获取 R2 Access Key ID
func GetCloudflareR2AccessKeyID() string {
	return baseconfig.GetR2AccessKeyID()
}

// GetCloudflareR2AccessKeySecret 获取 R2 Access Key Secret
func GetCloudflareR2AccessKeySecret() string {
	return baseconfig.GetR2AccessKeySecret()
}

// GetCloudflareR2Bucket 获取 R2 Bucket 名称（复用主配置）
func GetCloudflareR2Bucket() string {
	return baseconfig.GetR2Bucket()
}

// GetCloudflareR2Endpoint 获取 R2 Endpoint（根据 Account ID 构建）
func GetCloudflareR2Endpoint() string {
	accountID := baseconfig.GetR2AccountID()
	if accountID == "" {
		return ""
	}
	return "https://" + accountID + ".r2.cloudflarestorage.com"
}

// GetCloudflareR2PublicURL 获取 R2 公开访问 URL（复用主配置的 domain）
func GetCloudflareR2PublicURL() string {
	return baseconfig.GetR2Domain()
}
