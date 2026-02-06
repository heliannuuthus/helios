package alipay

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MPProvider 支付宝小程序 Provider
type MPProvider struct {
	appID      string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey // 支付宝公钥，用于验签
}

// NewMPProvider 创建支付宝小程序 Provider
func NewMPProvider() *MPProvider {
	cfg := config.Aegis()
	p := &MPProvider{
		appID: cfg.GetString("idps.alipay.appid"),
	}

	// 解析私钥
	privateKeyData := cfg.GetString("idps.alipay.secret")
	if privateKeyData != "" {
		privateKey, err := parsePrivateKey(privateKeyData)
		if err != nil {
			logger.Errorf("[Alipay] 解析私钥失败: %v", err)
		} else {
			p.privateKey = privateKey
		}
	}

	// 解析公钥（可选，用于验签）
	publicKeyData := cfg.GetString("idps.alipay.verify-key")
	if publicKeyData != "" {
		publicKey, err := parsePublicKey(publicKeyData)
		if err != nil {
			logger.Warnf("[Alipay] 解析公钥失败，跳过签名验证: %v", err)
		} else {
			p.publicKey = publicKey
		}
	}

	return p
}

// Type 返回 IDP 类型
func (*MPProvider) Type() string {
	return idp.TypeAlipayMP
}

// Exchange 用授权码换取用户信息
// proof: 小程序 login code
func (p *MPProvider) Login(ctx context.Context, proof string, _ ...any) (*idp.LoginResult, error) {
	if proof == "" {
		return nil, errors.New("code is required")
	}

	if err := p.validateConfig(); err != nil {
		return nil, err
	}

	code := proof
	logger.Infof("[Alipay] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 发送请求
	bodyStr, err := p.sendOAuthRequest(ctx, code)
	if err != nil {
		return nil, err
	}

	// 检查错误响应
	if err := p.checkErrorResponse(bodyStr); err != nil {
		return nil, err
	}

	// 验证签名
	if err := p.verifyResponseSign(bodyStr); err != nil {
		return nil, err
	}

	// 解析用户 ID
	return p.parseUserID(bodyStr)
}

// extractCode 提取授权码

// validateConfig 验证配置
func (p *MPProvider) validateConfig() error {
	if p.appID == "" || p.privateKey == nil {
		return errors.New("支付宝小程序 IdP 未配置")
	}
	return nil
}

// sendOAuthRequest 发送 OAuth 请求
func (p *MPProvider) sendOAuthRequest(ctx context.Context, code string) (string, error) {
	reqParams := p.buildRequestParams(code)

	signContent := buildSignContent(reqParams)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)

	sign, err := signWithRSA2(p.privateKey, signContent)
	if err != nil {
		logger.Errorf("[Alipay] 签名失败: %v", err)
		return "", fmt.Errorf("签名失败: %w", err)
	}
	reqParams["sign"] = sign

	form := url.Values{}
	for k, v := range reqParams {
		form.Add(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
	if err != nil {
		logger.Errorf("[Alipay] 构建请求失败: %v", err)
		return "", fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("[Alipay] 请求接口失败: %v", err)
		return "", fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Alipay] close response body failed: %v", err)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[Alipay] 读取响应失败: %v", err)
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Infof("[Alipay] 响应: %s", bodyStr)
	return bodyStr, nil
}

// buildRequestParams 构建请求参数
func (p *MPProvider) buildRequestParams(code string) map[string]string {
	return map[string]string{
		"app_id":     p.appID,
		"method":     "alipay.system.oauth.token",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       code,
	}
}

// checkErrorResponse 检查错误响应
func (p *MPProvider) checkErrorResponse(bodyStr string) error {
	errorCode := gjson.Get(bodyStr, "error_response.code").String()
	if errorCode == "" {
		return nil
	}
	errorMsg := gjson.Get(bodyStr, "error_response.msg").String()
	subMsg := gjson.Get(bodyStr, "error_response.sub_msg").String()
	logger.Errorf("[Alipay] 登录失败 - Code: %s, Msg: %s, SubMsg: %s", errorCode, errorMsg, subMsg)
	return fmt.Errorf("登录失败: %s - %s", errorMsg, subMsg)
}

// verifyResponseSign 验证响应签名
func (p *MPProvider) verifyResponseSign(bodyStr string) error {
	if p.publicKey == nil {
		return nil
	}

	respSign := gjson.Get(bodyStr, "sign").String()
	if respSign == "" {
		return nil
	}

	responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
	if !responseNode.Exists() {
		return nil
	}

	if err := verifySign(p.publicKey, responseNode.Raw, respSign); err != nil {
		logger.Errorf("[Alipay] 响应签名验证失败: %v", err)
		return fmt.Errorf("响应签名验证失败: %w", err)
	}
	logger.Infof("[Alipay] 响应签名验证成功")
	return nil
}

// parseUserID 解析用户 ID
func (p *MPProvider) parseUserID(bodyStr string) (*idp.LoginResult, error) {
	responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
	if !responseNode.Exists() {
		logger.Errorf("[Alipay] 响应中缺少 alipay_system_oauth_token_response")
		return nil, errors.New("响应中缺少 alipay_system_oauth_token_response")
	}

	userID := gjson.Get(bodyStr, "alipay_system_oauth_token_response.open_id").String()
	if userID == "" {
		logger.Errorf("[Alipay] 响应中缺少 open_id 字段")
		return nil, errors.New("响应中缺少 open_id 字段")
	}

	logger.Infof("[Alipay] 登录成功 - UserID: %s", userID)

	return &idp.LoginResult{
		ProviderID: userID,
		RawData:    fmt.Sprintf(`{"openid":"%s"}`, userID),
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (*MPProvider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	logger.Warnf("[Alipay] 支付宝获取 %s 暂未实现", infoType)
	return nil, fmt.Errorf("alipay does not support fetching %s yet", infoType)
}

// Prepare 准备前端所需的公开配置
func (p *MPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: "alipay:mp",
		Identifier: p.appID,
	}
}
