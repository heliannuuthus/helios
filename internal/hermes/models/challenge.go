package models

import (
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
)

// RateLimits 限流配置 map[window]limit
// 例如: {"1m": 1, "24h": 10} 表示每分钟 1 次，每天 10 次
type RateLimits map[string]int

// ServiceChallengeConfig 服务 Challenge 配置
type ServiceChallengeConfig struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	ServiceID string `gorm:"column:service_id;size:32;not null"`
	Type      string `gorm:"column:type;size:64;not null"` // email_otp / email_otp:login
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	// 变长字段
	LimitsJSON string `gorm:"column:limits;type:json;not null"` // {"1m": 1, "24h": 10}
}

func (ServiceChallengeConfig) TableName() string {
	return "t_service_challenge_config"
}

// GetLimits 解析限流配置
func (s *ServiceChallengeConfig) GetLimits() RateLimits {
	if s.LimitsJSON == "" {
		return nil
	}
	var limits RateLimits
	if err := json.Unmarshal([]byte(s.LimitsJSON), &limits); err != nil {
		return nil
	}
	return limits
}

// SetLimits 设置限流配置
func (s *ServiceChallengeConfig) SetLimits(limits RateLimits) error {
	data, err := json.Marshal(limits)
	if err != nil {
		return err
	}
	s.LimitsJSON = string(data)
	return nil
}
