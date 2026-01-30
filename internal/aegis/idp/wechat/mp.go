package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MPProvider 微信小程序 Provider
type MPProvider struct {
	appID     string
	appSecret string
}

// NewMPProvider 创建微信小程序 Provider
func NewMPProvider() *MPProvider {
	cfg := config.Auth()
	return &MPProvider{
		appID:     cfg.GetString("idps.wxmp.appid"),
		appSecret: cfg.GetString("idps.wxmp.secret"),
	}
}

// Type 返回 IDP 类型
func (p *MPProvider) Type() string {
	return idp.TypeWechatMP
}

// Exchange 用授权码换取用户信息
func (p *MPProvider) Exchange(ctx context.Context, params ...any) (*idp.ExchangeResult, error) {
	if len(params) < 1 {
		return nil, errors.New("code is required")
	}
	code, ok := params[0].(string)
	if !ok {
		return nil, errors.New("code must be a string")
	}
	if p.appID == "" || p.appSecret == "" {
		return nil, errors.New("微信小程序 IdP 未配置")
	}

	logger.Infof("[Wechat] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	reqParams := url.Values{}
	reqParams.Set("appid", p.appID)
	reqParams.Set("secret", p.appSecret)
	reqParams.Set("js_code", code)
	reqParams.Set("grant_type", "authorization_code")

	reqURL := "https://api.weixin.qq.com/sns/jscode2session?" + reqParams.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Wechat] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result code2SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Wechat] 解析响应失败: %v", err)
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Wechat] 登录失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return nil, fmt.Errorf("登录失败: %s", result.ErrMsg)
	}

	unionID := "(无)"
	if result.UnionID != "" {
		unionID = result.UnionID
	}
	logger.Infof("[Wechat] 登录成功 - OpenID: %s, UnionID: %s", result.OpenID, unionID)

	return &idp.ExchangeResult{
		ProviderID: result.OpenID,
		UnionID:    result.UnionID,
		RawData:    fmt.Sprintf(`{"openid":"%s","unionid":"%s"}`, result.OpenID, result.UnionID),
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (p *MPProvider) FetchAdditionalInfo(ctx context.Context, infoType string, params ...any) (*idp.AdditionalInfo, error) {
	switch infoType {
	case "phone":
		if len(params) < 1 {
			return nil, errors.New("phone code is required")
		}
		code, ok := params[0].(string)
		if !ok {
			return nil, errors.New("phone code must be a string")
		}
		phone, err := p.getPhoneNumber(ctx, code)
		if err != nil {
			return nil, err
		}
		return &idp.AdditionalInfo{
			Type:  "phone",
			Value: phone,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported info type: %s", infoType)
	}
}

// ToPublicConfig 转换为前端可用的公开配置
func (p *MPProvider) ToPublicConfig() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		ID:           "wechat-mp",
		ProviderType: idp.TypeWechatMP,
		Name:         "微信小程序",
		ClientID:     p.appID,
	}
}

// getPhoneNumber 获取微信手机号（内部方法）
func (p *MPProvider) getPhoneNumber(ctx context.Context, code string) (string, error) {
	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Wechat] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求微信接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result phoneNumberResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[Wechat] 解析手机号响应失败: %v", err)
		return "", fmt.Errorf("解析微信响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		logger.Errorf("[Wechat] 获取手机号失败 - ErrCode: %d, ErrMsg: %s", result.ErrCode, result.ErrMsg)
		return "", fmt.Errorf("微信获取手机号失败: %s", result.ErrMsg)
	}

	phone := result.PhoneInfo.PurePhoneNumber
	if phone == "" {
		phone = result.PhoneInfo.PhoneNumber
	}

	logger.Infof("[Wechat] 获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getAccessToken 获取微信 access_token
func (p *MPProvider) getAccessToken(ctx context.Context) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("微信小程序配置缺失")
	}

	reqURL := fmt.Sprintf("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=%s&secret=%s", p.appID, p.appSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求微信 access_token 失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[WeChat] close response body failed: %v", err)
		}
	}()

	var result accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析微信 access_token 响应失败: %w", err)
	}

	if result.ErrCode != 0 {
		return "", fmt.Errorf("获取微信 access_token 失败: %s", result.ErrMsg)
	}

	return result.AccessToken, nil
}

// 内部响应结构
type code2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

type phoneNumberResponse struct {
	ErrCode   int    `json:"errcode"`
	ErrMsg    string `json:"errmsg"`
	PhoneInfo struct {
		PhoneNumber     string `json:"phoneNumber"`
		PurePhoneNumber string `json:"purePhoneNumber"`
		CountryCode     string `json:"countryCode"`
	} `json:"phone_info"`
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}
