package authenticate

import (
	"context"

	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes/models"
)

// 编译期接口检查
var (
	_ authenticator.Authenticator    = (*IDPAuthenticator)(nil)
	_ authenticator.IdentityResolver = (*IDPAuthenticator)(nil)
)

// IDPAuthenticator IDP 认证器包装器
// 持有 idp.Provider，实现 Authenticator 接口
// 如果底层 Provider 实现了 idp.Exchangeable，则同时实现 ChallengeExchanger
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

// Authenticate 执行 IDP 认证（Login 流程）
// params: [proof string, ...extraParams]
func (a *IDPAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("proof must be a string")
	}

	extraParams := params[1:]
	connection := a.provider.Type()

	userInfo, err := a.provider.Login(ctx, proof, extraParams...)
	if err != nil {
		if connection == idp.TypeUser || connection == idp.TypeStaff {
			return false, autherrors.NewInvalidCredentials("authentication failed")
		}
		return false, autherrors.NewServerErrorf("idp login failed: %v", err)
	}

	if userInfo == nil {
		return false, autherrors.NewServerError("idp login returned nil user info")
	}

	domain := string(idp.GetDomain(connection))
	identity := userInfo.ToUserIdentity(domain, connection)
	flow.AddIdentity(identity, userInfo)

	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}

// Resolve 通过 principal 查找用户信息（委托 Provider.Resolve）
// 实现 authenticator.IdentityResolver 接口
func (a *IDPAuthenticator) Resolve(ctx context.Context, principal string) (*models.TUserInfo, error) {
	return a.provider.Resolve(ctx, principal)
}

// ==================== Exchanger 实现（条件） ====================

// Exchange 用平台授权码换取 principal（如小程序 code 换手机号）
// 仅在底层 Provider 实现了 idp.Exchangeable 时有效
func (a *IDPAuthenticator) Exchange(ctx context.Context, code string) (principal string, err error) {
	exchanger, ok := a.provider.(idp.Exchangeable)
	if !ok {
		return "", autherrors.NewInvalidRequestf("provider %s does not support exchange", a.provider.Type())
	}

	result, err := exchanger.Exchange(ctx, code, "")
	if err != nil {
		return "", err
	}

	return result.Value, nil
}

// IsExchangeable 检查底层 Provider 是否支持 Exchange
func (a *IDPAuthenticator) IsExchangeable() bool {
	_, ok := a.provider.(idp.Exchangeable)
	return ok
}
