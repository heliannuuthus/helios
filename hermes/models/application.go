package models

import (
	"strings"
	"time"
)

// Application 应用
type Application struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 业务字段
	DomainID       string  `gorm:"column:domain_id;size:32;not null"`
	AppID          string  `gorm:"column:app_id;size:64;not null;uniqueIndex"`
	Name           string  `gorm:"column:name;size:128;not null"`
	LogoURL        *string `gorm:"column:logo_url;size:512"`
	EncryptedKey   *string `gorm:"column:encrypted_key;size:256"`
	RedirectURIs   *string `gorm:"column:redirect_uris;size:2048"`
	AllowedOrigins *string `gorm:"column:allowed_origins;size:1024"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (Application) TableName() string {
	return "t_application"
}

// ApplicationIDPConfig 应用 IDP 配置
type ApplicationIDPConfig struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	AppID    string `gorm:"column:app_id;size:64;not null"`
	Type     string `gorm:"column:type;size:32;not null"` // github/google/wechat-mp/user/staff
	Priority int    `gorm:"column:priority;not null;default:0"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	// 变长字段（逗号分隔）
	Strategy *string `gorm:"column:strategy;size:256"` // password,webauthn（仅 user/staff 需要）
	Delegate *string `gorm:"column:delegate;size:256"` // email_otp,totp,webauthn
	Require  *string `gorm:"column:require;size:256"`  // captcha
}

func (ApplicationIDPConfig) TableName() string {
	return "t_application_idp_config"
}

// GetStrategyList 获取策略列表
func (a *ApplicationIDPConfig) GetStrategyList() []string {
	if a.Strategy == nil || *a.Strategy == "" {
		return nil
	}
	return strings.Split(*a.Strategy, ",")
}

// GetDelegateList 获取委托 MFA 列表
func (a *ApplicationIDPConfig) GetDelegateList() []string {
	if a.Delegate == nil || *a.Delegate == "" {
		return nil
	}
	return strings.Split(*a.Delegate, ",")
}

// GetRequireList 获取前置验证列表
func (a *ApplicationIDPConfig) GetRequireList() []string {
	if a.Require == nil || *a.Require == "" {
		return nil
	}
	return strings.Split(*a.Require, ",")
}

// ApplicationServiceRelation 应用服务关系
type ApplicationServiceRelation struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	AppID     string `gorm:"column:app_id;size:64;not null"`
	ServiceID string `gorm:"column:service_id;size:32;not null;index"`
	Relation  string `gorm:"column:relation;size:32;not null;default:*"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (ApplicationServiceRelation) TableName() string {
	return "t_application_service_relation"
}
