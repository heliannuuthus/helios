package github

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
	tokenURL  = "https://github.com/login/oauth/access_token"
	userURL   = "https://api.github.com/user"
	emailsURL = "https://api.github.com/user/emails"
)

// Provider GitHub OAuth Provider
type Provider struct {
	clientID     string
	clientSecret string
}

// NewProvider 创建 GitHub Provider
func NewProvider() *Provider {
	cfg := config.Aegis()
	return &Provider{
		clientID:     cfg.GetString("idps.github.client-id"),
		clientSecret: cfg.GetString("idps.github.client-secret"),
	}
}

// Type 返回 IDP 类型
func (*Provider) Type() string {
	return idp.TypeGithub
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
		return nil, errors.New("GitHub IdP 未配置")
	}

	logger.Infof("[GitHub] 登录请求 - Code: %s...", code[:min(len(code), 10)])

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[GitHub] 请求 access_token 失败: %v", err)
		return "", fmt.Errorf("请求 access_token 失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[GitHub] close response body failed: %v", err)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[GitHub] access_token 响应: %s", bodyStr)

	// 检查错误
	if errMsg := gjson.Get(bodyStr, "error").String(); errMsg != "" {
		errDesc := gjson.Get(bodyStr, "error_description").String()
		logger.Errorf("[GitHub] 获取 access_token 失败: %s - %s", errMsg, errDesc)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[GitHub] 请求用户信息失败: %v", err)
		return nil, fmt.Errorf("请求用户信息失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[GitHub] close response body failed: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			logger.Warnf("[GitHub] read error response body failed: %v", readErr)
		}
		logger.Errorf("[GitHub] 获取用户信息失败: HTTP %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("获取用户信息失败: HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[GitHub] 用户信息响应: %s", bodyStr)

	// 提取用户 ID（GitHub 使用数字 ID）
	userID := gjson.Get(bodyStr, "id").String()
	if userID == "" {
		return nil, errors.New("响应中缺少 id 字段")
	}

	login := gjson.Get(bodyStr, "login").String()

	// 如果 /user API 没有返回 email，尝试从 /user/emails 获取
	email := gjson.Get(bodyStr, "email").String()
	if email == "" {
		email = p.getPrimaryEmail(ctx, accessToken)
		if email != "" {
			// 将 email 添加到 rawData 中
			bodyStr = strings.TrimSuffix(bodyStr, "}") + `,"email":"` + email + `"}`
		}
	}

	logger.Infof("[GitHub] 登录成功 - UserID: %s, Login: %s, Email: %s", userID, login, email)

	return &idp.ExchangeResult{
		ProviderID: userID,
		RawData:    bodyStr,
	}, nil
}

// getPrimaryEmail 获取用户主邮箱
func (p *Provider) getPrimaryEmail(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsURL, nil)
	if err != nil {
		logger.Warnf("[GitHub] 创建 emails 请求失败: %v", err)
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Warnf("[GitHub] 请求 emails 失败: %v", err)
		return ""
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[GitHub] close emails response body failed: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logger.Warnf("[GitHub] 获取 emails 失败: HTTP %d", resp.StatusCode)
		return ""
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("[GitHub] 读取 emails 响应失败: %v", err)
		return ""
	}

	bodyStr := string(bodyBytes)
	logger.Debugf("[GitHub] emails 响应: %s", bodyStr)

	// 遍历邮箱列表，优先返回 primary 且 verified 的邮箱
	emails := gjson.Parse(bodyStr).Array()
	var fallbackEmail string
	for _, e := range emails {
		email := e.Get("email").String()
		primary := e.Get("primary").Bool()
		verified := e.Get("verified").Bool()

		if primary && verified {
			return email
		}
		if verified && fallbackEmail == "" {
			fallbackEmail = email
		}
	}

	return fallbackEmail
}

// FetchAdditionalInfo 补充获取用户信息
func (*Provider) FetchAdditionalInfo(ctx context.Context, infoType string, params ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("GitHub does not support fetching %s", infoType)
}

// Prepare 准备前端所需的公开配置
func (p *Provider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: "github",
		Identifier: p.clientID,
	}
}
