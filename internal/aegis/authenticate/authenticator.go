package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// Authenticator 认证器接口
type Authenticator interface {
	// Supports 判断是否支持该 connection
	Supports(connection string) bool

	// Authenticate 执行认证
	// connCfg: 从 flow.ConnectionMap 获取的 ConnectionConfig
	// proof: 认证凭证（OAuth code / password / OTP code 等）
	// params: 额外参数（identifier 等）
	Authenticate(ctx context.Context, connCfg *types.ConnectionConfig, proof string, params ...any) (*AuthResult, error)
}
