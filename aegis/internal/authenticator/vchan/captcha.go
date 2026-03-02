package vchan

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/internal/authenticator/captcha"
	"github.com/heliannuuthus/helios/aegis/internal/types"
)

// TypeCaptcha captcha 渠道类型标识
const TypeCaptcha = "captcha"

// CaptchaProvider captcha 验证渠道 Provider
// 内部持有多个 strategy verifiers，根据请求中的 strategy 路由到对应 verifier
type CaptchaProvider struct {
	verifiers       map[string]captcha.Verifier // strategy -> verifier
	defaultStrategy string                      // 默认 strategy（第一个注册的）
}

// NewCaptchaProvider 创建 captcha 验证渠道 Provider
// 支持传入多个 verifier，按 GetProvider() 作为 strategy key
func NewCaptchaProvider(verifiers ...captcha.Verifier) *CaptchaProvider {
	p := &CaptchaProvider{
		verifiers: make(map[string]captcha.Verifier),
	}
	for _, v := range verifiers {
		strategy := v.GetProvider()
		p.verifiers[strategy] = v
		if p.defaultStrategy == "" {
			p.defaultStrategy = strategy
		}
	}
	return p
}

// Type 返回渠道类型标识
func (*CaptchaProvider) Type() string {
	return TypeCaptcha
}

func (p *CaptchaProvider) Initiate(_ context.Context, _ *types.Challenge) error {
	return nil
}

// Verify 验证 captcha proof
// params[0]: strategy (string) - 必填
// params[1]: remoteIP (string) - 可选
func (p *CaptchaProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	var strategy, remoteIP string
	if len(params) >= 1 {
		if s, ok := params[0].(string); ok {
			strategy = s
		}
	}
	if len(params) >= 2 {
		if ip, ok := params[1].(string); ok {
			remoteIP = ip
		}
	}

	verifier, err := p.getVerifier(strategy)
	if err != nil {
		return false, err
	}
	return verifier.Verify(ctx, proof, remoteIP)
}

func (p *CaptchaProvider) getVerifier(strategy string) (captcha.Verifier, error) {
	if strategy == "" {
		strategy = p.defaultStrategy
	}
	v, ok := p.verifiers[strategy]
	if !ok {
		return nil, fmt.Errorf("unsupported captcha strategy: %s", strategy)
	}
	return v, nil
}

// Prepare 返回前端公开配置
func (p *CaptchaProvider) Prepare() *types.ConnectionConfig {
	strategies := make([]string, 0, len(p.verifiers))
	var identifier string
	for strategy, v := range p.verifiers {
		strategies = append(strategies, strategy)
		if strategy == p.defaultStrategy {
			identifier = v.GetIdentifier()
		}
	}
	return &types.ConnectionConfig{
		Connection: TypeCaptcha,
		Identifier: identifier,
		Strategy:   strategies,
	}
}

// GetIdentifier 获取默认 strategy 的站点密钥
func (p *CaptchaProvider) GetIdentifier() string {
	if v, ok := p.verifiers[p.defaultStrategy]; ok {
		return v.GetIdentifier()
	}
	return ""
}

// GetProvider 获取默认 strategy 名称
func (p *CaptchaProvider) GetProvider() string {
	return p.defaultStrategy
}
