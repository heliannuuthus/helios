package cache

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
)

// ==================== AuthFlow（Redis）====================

// AuthFlow 认证流程（简化版，详细定义在 types/authflow.go）
type AuthFlow struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Data      []byte    `json:"data"` // JSON 序列化的完整 AuthFlow
}

// SaveAuthFlow 保存 AuthFlow
func (cm *Manager) SaveAuthFlow(ctx context.Context, flowID string, data []byte) error {
	prefix := config.GetAegisCacheKeyPrefix("auth_flow")
	expiresIn := config.GetAegisAuthFlowExpiresIn()
	return cm.redis.Set(ctx, prefix+flowID, string(data), expiresIn)
}

// GetAuthFlow 获取 AuthFlow
func (cm *Manager) GetAuthFlow(ctx context.Context, flowID string) ([]byte, error) {
	prefix := config.GetAegisCacheKeyPrefix("auth_flow")
	data, err := cm.redis.Get(ctx, prefix+flowID)
	if err != nil {
		return nil, ErrAuthFlowNotFound
	}
	return []byte(data), nil
}

// DeleteAuthFlow 删除 AuthFlow（设置短 TTL 让其自然过期）
func (cm *Manager) DeleteAuthFlow(ctx context.Context, flowID string) error {
	prefix := config.GetAegisCacheKeyPrefix("auth_flow")
	// 设置 5 秒后过期，而不是立即删除
	data, err := cm.redis.Get(ctx, prefix+flowID)
	if err != nil {
		return nil // 不存在就算了
	}
	return cm.redis.Set(ctx, prefix+flowID, data, 5*time.Second)
}
