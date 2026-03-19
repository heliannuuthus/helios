package models

import (
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// CrossDomainID 底层约定：domain_id 为该值时表示跨域服务，可被多域共用。不在 API 响应中暴露，上层用请求的 domain_id 表示。
const CrossDomainID = "-"

// RateLimits 限流配置 map[window]limit
// 例如: {"1m": 1, "24h": 10} 表示每分钟 1 次，每天 10 次
type RateLimits map[string]int

// Service 服务（DB 模型，不直接序列化到 API，请使用 dto.ToServiceResponse）
type Service struct {
	ID                   uint                      `gorm:"primaryKey;autoIncrement;column:_id"`
	DomainID             string                    `gorm:"column:domain_id;size:32;not null"`
	ServiceID            string                    `gorm:"column:service_id;size:32;not null;uniqueIndex"`
	Name                 string                    `gorm:"column:name;size:128;not null"`
	Description          *string                   `gorm:"column:description;size:512"`
	LogoURL              *string                   `gorm:"column:logo_url;size:512"`
	AccessTokenExpiresIn uint                      `gorm:"column:access_token_expires_in;not null;default:7200"`
	RequiredIdentities   *string                   `gorm:"column:required_identities;size:512"`
	CreatedAt            time.Time                 `gorm:"column:created_at;not null"`
	UpdatedAt            time.Time                 `gorm:"column:updated_at;not null"`
	ChallengeSettings    []ServiceChallengeSetting `gorm:"foreignKey:ServiceID;references:ServiceID"`
}

func (Service) TableName() string { return "t_service" }

func (s Service) PrimaryKey() uint { return s.ID }

// ServiceWithKey 带密钥的 Service（Main/Keys 不序列化到 API）
type ServiceWithKey struct {
	Service
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥（包括主密钥和轮换中的旧密钥）
}

// GetRequiredIdentities 解析访问该服务需要绑定的身份类型
func (s *Service) GetRequiredIdentities() []string {
	if s.RequiredIdentities == nil || *s.RequiredIdentities == "" {
		return nil
	}
	var identities []string
	if err := json.Unmarshal([]byte(*s.RequiredIdentities), &identities); err != nil {
		logger.Warnf("[Service] unmarshal required identities failed: %v", err)
		return nil
	}
	return identities
}

// ServiceChallengeSetting 服务 Challenge 配置（按 channel_type 或 channel_type:biz_type 维度）
type ServiceChallengeSetting struct {
	ID        uint       `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	ServiceID string     `gorm:"column:service_id;size:32;not null;index" json:"service_id"`
	Type      string     `gorm:"column:type;size:64;not null" json:"type"`
	ExpiresIn uint       `gorm:"column:expires_in;not null;default:300" json:"expires_in"`
	Limits    RateLimits `gorm:"column:limits;serializer:json" json:"limits"`
	CreatedAt time.Time  `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time  `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (ServiceChallengeSetting) TableName() string { return "t_service_challenge_setting" }
