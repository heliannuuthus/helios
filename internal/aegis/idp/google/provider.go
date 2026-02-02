package google

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	tokenURL    = "https://oauth2.googleapis.com/token"
	userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// Provider Google OAuth Provider
type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
}

// NewProvider 创建 Google Provider
func NewProvider() *Provider {
	cfg := config.Aegis()
	return &Provider{
		clientID:     cfg.GetString("idps.google.client-id"),
		clientSecret: cfg.GetString("idps.google.client-secret"),
		redirectURI:  cfg.GetString("idps.google.redirect-uri"),
	}
}

// Type 返回 IDP 类型
func (*Provider) Type() string {
	return idp.TypeGoogle
}

// Exchange 用授权码换取用户信息
func (p *Provider) Exchange(ctx context.Context, params ...any) (*idp.ExchangeResult, error) {
	if len(params) < 1 {
		return nil, errors.New("code is required")
	}
	code, ok := params[0].(string)
	if !ok {
		return nil, errors.New("code must be a string")
	}

	if p.clientID == "" || p.clientSecret == "" {
		return nil, errors.New("google IdP 未配置")
	}

	logger.Infof("[Google] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 第一步：用 code 换取 access_token
	accessToken, err := p.getAccessToken(ctx, code)
	if err != nil {
		return nil, err
	}

	// 第二步：用 access_token 获取用户信息
	return p.getUserInfo(ctx, accessToken)
}

// getAccessToken 用 code 换取 access_token
func (p *Provider) getAccessToken(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	if p.redirectURI != "" {
		form.Set("redirect_uri", p.redirectURI)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Google] 请求 access_token 失败: %v", err)
		return "", fmt.Errorf("请求 access_token 失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Google] close response body failed: %v", err)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[Google] access_token 响应: %s", bodyStr)

	// 检查错误
	if errMsg := gjson.Get(bodyStr, "error").String(); errMsg != "" {
		errDesc := gjson.Get(bodyStr, "error_description").String()
		logger.Errorf("[Google] 获取 access_token 失败: %s - %s", errMsg, errDesc)
		return "", fmt.Errorf("获取 access_token 失败: %s", errDesc)
	}

	accessToken := gjson.Get(bodyStr, "access_token").String()
	if accessToken == "" {
		return "", errors.New("响应中缺少 access_token")
	}

	return accessToken, nil
}

// getUserInfo 获取用户信息
func (p *Provider) getUserInfo(ctx context.Context, accessToken string) (*idp.ExchangeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[Google] 请求用户信息失败: %v", err)
		return nil, fmt.Errorf("请求用户信息失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Google] close response body failed: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			logger.Warnf("[Google] read error response body failed: %v", readErr)
		}
		logger.Errorf("[Google] 获取用户信息失败: HTTP %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("获取用户信息失败: HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[Google] 用户信息响应: %s", bodyStr)

	// 提取用户 ID（Google 使用 sub 或 id 字段）
	userID := gjson.Get(bodyStr, "id").String()
	if userID == "" {
		userID = gjson.Get(bodyStr, "sub").String()
	}
	if userID == "" {
		return nil, errors.New("响应中缺少 id/sub 字段")
	}

	email := gjson.Get(bodyStr, "email").String()
	logger.Infof("[Google] 登录成功 - UserID: %s, Email: %s", userID, email)

	return &idp.ExchangeResult{
		ProviderID: userID,
		RawData:    bodyStr,
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (*Provider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("google does not support fetching %s", infoType)
}

// ToPublicConfig 转换为前端可用的公开配置
func (p *Provider) ToPublicConfig() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: "google",
		Strategy:   []string{"oauth"},
	}
}
