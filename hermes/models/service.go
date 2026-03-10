package models

import (
	"time"
)

// RateLimits 限流配置 map[window]limit
// 例如: {"1m": 1, "24h": 10} 表示每分钟 1 次，每天 10 次
type RateLimits map[string]int

// Service 服务（DB 模型，不直接序列化到 API，请使用 dto.ToServiceResponse）
type Service struct {
	ID                    uint    `gorm:"primaryKey;autoIncrement;column:_id"`
	DomainID              string  `gorm:"column:domain_id;size:32;not null"`
	ServiceID             string  `gorm:"column:service_id;size:32;not null;uniqueIndex"`
	Name                  string  `gorm:"column:name;size:128;not null"`
	Description           *string `gorm:"column:description;size:512"`
	AccessTokenExpiresIn  uint    `gorm:"column:access_token_expires_in;not null;default:7200"`
	RefreshTokenExpiresIn uint    `gorm:"column:refresh_token_expires_in;not null;default:604800"`
	RequiredIdentities    *string `gorm:"column:required_identities;size:512"`
	CreatedAt             time.Time `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time `gorm:"column:updated_at;not null"`
	ChallengeSettings     []ServiceChallengeSetting `gorm:"foreignKey:ServiceID;references:ServiceID"`
}

func (Service) TableName() string {
	return "t_service"
}

// ServiceChallengeSetting 服务 Challenge 配置（按 channel_type 或 channel_type:biz_type 维度）
type ServiceChallengeSetting struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	// 外键
	ServiceID string `gorm:"column:service_id;size:32;not null;index" json:"service_id"`
	// 配置维度
	Type string `gorm:"column:type;size:64;not null" json:"type"` // email_otp / email_otp:login

	// Challenge 基础配置
	ExpiresIn uint `gorm:"column:expires_in;not null;default:300" json:"expires_in"` // Challenge 有效期（秒）

	// 限流配置
	Limits RateLimits `gorm:"column:limits;serializer:json" json:"limits"` // {"1m": 1, "24h": 10}

	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (ServiceChallengeSetting) TableName() string {
	return "t_service_challenge_setting"
}
