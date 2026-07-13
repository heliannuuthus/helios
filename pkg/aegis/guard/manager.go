package guard

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/heliannuuthus/pkg/aegis/service"
	"github.com/heliannuuthus/pkg/aegis/utilities/key"
)

const serviceSeedSize = 48

var globalManager *service.Manager

// NewTokenManager 初始化全局 token Manager。应在服务启动时调用一次。
func NewTokenManager(endpoint string, seedProvider key.Provider) {
	globalManager = service.NewManager(endpoint, seedProvider)
}

// NewServiceTokenManager 使用单个服务的本地 seed 初始化全局 token Manager。
// provider 仅向期望的 audience 提供密钥，防止服务误验证其他 audience 的 token。
func NewServiceTokenManager(endpoint, audience string, seed []byte) error {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return fmt.Errorf("aegis issuer 未配置")
	}
	if strings.TrimSpace(audience) == "" {
		return fmt.Errorf("aegis audience 未配置")
	}
	if len(seed) != serviceSeedSize {
		return fmt.Errorf("服务密钥长度错误: 期望 %d 字节, 实际 %d 字节", serviceSeedSize, len(seed))
	}

	NewTokenManager(endpoint, newServiceSeedProvider(audience, seed))
	return nil
}

func newServiceSeedProvider(audience string, seed []byte) key.Provider {
	serviceSeed := bytes.Clone(seed)
	return key.SingleOf(func(_ context.Context, id string) ([]byte, error) {
		if id != audience {
			return nil, fmt.Errorf("%w: audience %s", key.ErrNotFound, id)
		}
		return bytes.Clone(serviceSeed), nil
	})
}

// GetTokenManager 返回全局 token Manager。
func GetTokenManager() *service.Manager {
	return globalManager
}
