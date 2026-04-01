package models

import (
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// RateLimits 限流配置 map[window]limit
type RateLimits map[string]int

// Service 服务（从 proto 转换，不含 GORM 标签）
type Service struct {
	ID                   uint                      `json:"_id"`
	DomainID             string                    `json:"domain_id"`
	ServiceID            string                    `json:"service_id"`
	Name                 string                    `json:"name"`
	Description          *string                   `json:"description,omitempty"`
	LogoURL              *string                   `json:"logo_url,omitempty"`
	AccessTokenExpiresIn uint                      `json:"access_token_expires_in"`
	RequiredIdentities   *string                   `json:"required_identities,omitempty"`
	CreatedAt            time.Time                 `json:"created_at"`
	UpdatedAt            time.Time                 `json:"updated_at"`
	ChallengeSettings    []ServiceChallengeSetting `json:"challenge_settings,omitempty"`
}

// ServiceWithKey 带密钥的 Service（Main/Keys 不序列化到 API）
type ServiceWithKey struct {
	Service
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥
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

// ServiceChallengeSetting 服务 Challenge 配置（从 proto 转换）
type ServiceChallengeSetting struct {
	ID        uint       `json:"_id"`
	ServiceID string     `json:"service_id"`
	Type      string     `json:"type"`
	ExpiresIn uint       `json:"expires_in"`
	Limits    RateLimits `json:"limits"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}
