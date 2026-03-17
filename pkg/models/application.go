package models

import (
	"strings"
	"time"
)

// Application 应用（控制 id_token、refresh_token 有效期；access_token 由服务控制）
type Application struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	// 业务字段
	DomainID                      string  `gorm:"column:domain_id;size:32;not null" json:"domain_id"`
	AppID                         string  `gorm:"column:app_id;size:64;not null;uniqueIndex" json:"app_id"`
	Name                          string  `gorm:"column:name;size:128;not null" json:"name"`
	Description                   *string `gorm:"column:description;size:512" json:"description,omitempty"`
	LogoURL                       *string `gorm:"column:logo_url;size:512" json:"logo_url,omitempty"`
	AllowedRedirectURIs           *string `gorm:"column:redirect_uris;size:2048" json:"allowed_redirect_uris,omitempty"`
	AllowedOrigins                *string `gorm:"column:allowed_origins;size:1024" json:"allowed_origins,omitempty"`
	AllowedLogoutURIs             *string `gorm:"column:allowed_logout_uris;size:1024" json:"allowed_logout_uris,omitempty"`
	IDTokenExpiresIn              uint    `gorm:"column:id_token_expires_in;not null;default:3600" json:"id_token_expires_in"`                          // ID Token 有效期（秒）
	RefreshTokenExpiresIn         uint    `gorm:"column:refresh_token_expires_in;not null;default:604800" json:"refresh_token_expires_in"`              // Refresh Token 沉寂有效期（秒）
	RefreshTokenAbsoluteExpiresIn uint    `gorm:"column:refresh_token_absolute_expires_in;not null;default:0" json:"refresh_token_absolute_expires_in"` // 绝对有效期（秒），0=不限制
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (Application) TableName() string {
	return "t_application"
}

func (a Application) PrimaryKey() uint { return a.ID }

// ApplicationIDPConfig 应用 IDP 配置 + 可选凭证覆盖
type ApplicationIDPConfig struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	AppID     string    `gorm:"column:app_id;size:64;not null" json:"app_id"`
	Type      string    `gorm:"column:type;size:32;not null" json:"type"`
	Priority  int       `gorm:"column:priority;not null;default:0" json:"priority"`
	Strategy  *string   `gorm:"column:strategy;size:256" json:"strategy,omitempty"`
	TAppID    *string   `gorm:"column:t_app_id;size:256" json:"t_app_id,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (ApplicationIDPConfig) TableName() string {
	return "t_application_idp_config"
}

func (a *ApplicationIDPConfig) GetStrategyList() []string {
	if a.Strategy == nil || *a.Strategy == "" {
		return nil
	}
	return strings.Split(*a.Strategy, ",")
}

// ApplicationServiceRelation 应用服务关系
type ApplicationServiceRelation struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	// 固定长度字段
	AppID     string    `gorm:"column:app_id;size:64;not null" json:"app_id"`
	ServiceID string    `gorm:"column:service_id;size:32;not null;index" json:"service_id"`
	Relation  string    `gorm:"column:relation;size:32;not null;default:*" json:"relation"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

func (ApplicationServiceRelation) TableName() string {
	return "t_application_service_relation"
}
