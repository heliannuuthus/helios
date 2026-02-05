package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate/authenticator/idp"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// IDPAuthenticator IDP 认证器
type IDPAuthenticator struct {
	registry *idp.Registry
}

// NewIDPAuthenticator 创建 IDP 认证器
func NewIDPAuthenticator(registry *idp.Registry) *IDPAuthenticator {
	return &IDPAuthenticator{
		registry: registry,
	}
}

// Supports 判断是否支持该 connection
func (a *IDPAuthenticator) Supports(connection string) bool {
	return a.registry.Has(connection)
}

// Authenticate 执行认证
// connCfg: ConnectionConfig（从 flow.ConnectionMap 获取）
// proof: 认证凭证（OAuth code / password）
// params: 额外参数（如 identifier）
func (a *IDPAuthenticator) Authenticate(ctx context.Context, connCfg *types.ConnectionConfig, proof string, params ...any) (*AuthResult, error) {
	connection := connCfg.Connection
	provider, ok := a.registry.Get(connection)
	if !ok {
		return nil, autherrors.NewInvalidRequestf("unsupported idp: %s", connection)
	}

	// 调用 Provider.Login，将 proof 和 params 一起传递
	result, err := provider.Login(ctx, proof, params...)
	if err != nil {
		// 系统账号密码登录返回统一错误（安全考虑）
		if connection == idp.TypeUser || connection == idp.TypeOper {
			return nil, autherrors.NewInvalidCredentials("authentication failed")
		}
		return nil, autherrors.NewServerErrorf("idp exchange failed: %v", err)
	}

	// 转换 UserInfo
	var userInfo *UserInfo
	if result.UserInfo != nil {
		userInfo = &UserInfo{
			Nickname: result.UserInfo.Nickname,
			Email:    result.UserInfo.Email,
			Phone:    result.UserInfo.Phone,
			Picture:  result.UserInfo.Picture,
		}
	}

	return &AuthResult{
		ProviderID: result.ProviderID,
		UserInfo:   userInfo,
		RawData:    result.RawData,
	}, nil
}
