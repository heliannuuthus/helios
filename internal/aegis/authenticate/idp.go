package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// IDPAuthenticator IDP 认证器胶水层
// 一对一包装一个 idp.Provider，实现统一的 Authenticator 接口
type IDPAuthenticator struct {
	provider idp.Provider
}

// NewIDPAuthenticator 创建 IDP 认证器
func NewIDPAuthenticator(provider idp.Provider) *IDPAuthenticator {
	return &IDPAuthenticator{
		provider: provider,
	}
}

// Type 返回认证器类型标识
func (a *IDPAuthenticator) Type() string {
	return a.provider.Type()
}

// ConnectionType 返回连接类型
func (a *IDPAuthenticator) ConnectionType() types.ConnectionType {
	return types.ConnTypeIDP
}

// Prepare 返回完整配置（含 Type）
func (a *IDPAuthenticator) Prepare() *types.ConnectionConfig {
	cfg := a.provider.Prepare()
	if cfg != nil {
		cfg.Type = types.ConnTypeIDP
	}
	return cfg
}

// Authenticate 执行 IDP 认证
// 内部调用 provider.Login()，将结果转换为 UserIdentity 存入 flow.Identities，
// 设置当前 ConnectionConfig.Verified = true，返回 true
// params: [proof string, ...extraParams]
func (a *IDPAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	// 从 params 中提取 proof
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("proof must be a string")
	}

	// 剩余 params 传给 provider
	extraParams := params[1:]

	connection := a.provider.Type()

	// 调用 Provider.Login
	userInfo, err := a.provider.Login(ctx, proof, extraParams...)
	if err != nil {
		// 系统账号密码登录返回统一错误（安全考虑）
		if connection == idp.TypeUser || connection == idp.TypeOper {
			return false, autherrors.NewInvalidCredentials("authentication failed")
		}
		return false, autherrors.NewServerErrorf("idp login failed: %v", err)
	}

	if userInfo == nil {
		return false, autherrors.NewServerError("idp login returned nil user info")
	}

	// 将 TUserInfo 转为 UserIdentity，连同用户信息一起存入 flow
	domain := string(idp.GetDomain(connection))
	identity := userInfo.ToUserIdentity(domain, connection)
	flow.AddIdentity(identity, userInfo)

	// 标记当前 connection 已验证
	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}
