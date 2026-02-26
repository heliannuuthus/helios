package captcha

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	// TurnstileVerifyURL Cloudflare Turnstile 验证 API
	TurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	// ProviderTurnstile 提供商名称
	ProviderTurnstile = "turnstile"
)

// TurnstileVerifier Cloudflare Turnstile 验证器
type TurnstileVerifier struct {
	siteKey   string
	secretKey string
	client    *http.Client
}

// NewTurnstileVerifier 创建 Turnstile 验证器
func NewTurnstileVerifier(siteKey, secretKey string) *TurnstileVerifier {
	return &TurnstileVerifier{
		siteKey:   siteKey,
		secretKey: secretKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Verify 验证 Turnstile token
func (v *TurnstileVerifier) Verify(ctx context.Context, proof, remoteIP string) (bool, error) {
	if proof == "" {
		return false, fmt.Errorf("empty token")
	}

	// 构建请求参数
	data := url.Values{}
	data.Set("secret", v.secretKey)
	data.Set("response", proof)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	// 发送请求（参数通过 POST body 传递，Turnstile API 不支持 query string）
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TurnstileVerifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[Turnstile] close response body failed: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// 解析响应
	var result TurnstileResponse
	if err := json.UnmarshalRead(resp.Body, &result); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}

	if !result.Success {
		return false, fmt.Errorf("verification failed: %v", result.ErrorCodes)
	}

	return true, nil
}

// GetIdentifier 获取站点密钥
func (v *TurnstileVerifier) GetIdentifier() string {
	return v.siteKey
}

// GetProvider 获取提供商名称
func (v *TurnstileVerifier) GetProvider() string {
	return ProviderTurnstile
}

// TurnstileResponse Turnstile API 响应
type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	Action      string   `json:"action,omitempty"`
	CData       string   `json:"cdata,omitempty"`
}
