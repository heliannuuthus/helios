package auth

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/idp/alipay"
	"github.com/heliannuuthus/helios/internal/auth/idp/tt"
	"github.com/heliannuuthus/helios/internal/auth/idp/wechat"
)

// IDPResult IDP 认证结果
type IDPResult struct {
	ProviderID string // IDP 侧用户唯一标识
	UnionID    string // 联合 ID（可选）
	RawData    string // 原始数据 JSON
}

// IDPManager IDP 管理器
type IDPManager struct {
	wechatClient *wechat.Client
	ttClient     *tt.Client
	alipayClient *alipay.Client
}

// NewIDPManager 创建 IDP 管理器
func NewIDPManager() *IDPManager {
	return &IDPManager{
		wechatClient: wechat.NewClient(),
		ttClient:     tt.NewClient(),
		alipayClient: alipay.NewClient(),
	}
}

// Exchange 用 IDP code 换取用户信息
func (m *IDPManager) Exchange(ctx context.Context, idp IDP, code string) (*IDPResult, error) {
	switch idp {
	case IDPWechatMP:
		return m.exchangeWechatMP(code)
	case IDPTTMP:
		return m.exchangeTTMP(code)
	case IDPAlipayMP:
		return m.exchangeAlipayMP(code)
	default:
		return nil, fmt.Errorf("unsupported idp: %s", idp)
	}
}

func (m *IDPManager) exchangeWechatMP(code string) (*IDPResult, error) {
	result, err := m.wechatClient.Code2Session(code)
	if err != nil {
		return nil, err
	}
	return &IDPResult{
		ProviderID: result.OpenID,
		UnionID:    result.UnionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, result.OpenID, result.UnionID),
	}, nil
}

func (m *IDPManager) exchangeTTMP(code string) (*IDPResult, error) {
	result, err := m.ttClient.Code2Session(code)
	if err != nil {
		return nil, err
	}
	return &IDPResult{
		ProviderID: result.OpenID,
		UnionID:    result.UnionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, result.OpenID, result.UnionID),
	}, nil
}

func (m *IDPManager) exchangeAlipayMP(code string) (*IDPResult, error) {
	result, err := m.alipayClient.Code2Session(code)
	if err != nil {
		return nil, err
	}
	return &IDPResult{
		ProviderID: result.OpenID,
		UnionID:    result.UnionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, result.OpenID, result.UnionID),
	}, nil
}

// GetPhoneNumber 获取手机号
func (m *IDPManager) GetPhoneNumber(idp IDP, code string) (string, error) {
	switch idp {
	case IDPWechatMP:
		return m.wechatClient.GetPhoneNumber(code)
	case IDPTTMP:
		return m.ttClient.GetPhoneNumber(code)
	case IDPAlipayMP:
		return m.alipayClient.GetPhoneNumber(code)
	default:
		return "", fmt.Errorf("unsupported idp for phone: %s", idp)
	}
}
