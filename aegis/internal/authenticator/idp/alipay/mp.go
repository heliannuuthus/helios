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

	"github.com/heliannuuthus/helios/aegis/internal/config"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/aegis/internal/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MPProvider 支付宝小程序 Provider
type MPProvider struct {
	resolver  idp.KeyResolver
	publicKey *rsa.PublicKey // 支付宝公钥，用于验签
}

// NewMPProvider 创建支付宝小程序 Provider
func NewMPProvider(resolver idp.KeyResolver) *MPProvider {
	cfg := config.Cfg()
	p := &MPProvider{
		resolver: resolver,
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
// params[0]: appID (string) — 用于动态解析 IDP 密钥
func (p *MPProvider) Login(ctx context.Context, proof string, params ...any) (*models.TUserInfo, error) {
	if proof == "" {
		return nil, errors.New("code is required")
	}

	appID := ""
	if len(params) > 0 {
		if v, ok := params[0].(string); ok {
			appID = v
		}
	}

	alipayAppID, alipaySecret, err := p.resolver.ResolveIDPKey(ctx, appID, idp.TypeAlipayMP)
	if err != nil {
		return nil, fmt.Errorf("解析支付宝小程序 IDP 密钥失败: %w", err)
	}

	privateKey, err := parsePrivateKey(alipaySecret)
	if err != nil {
		return nil, fmt.Errorf("解析支付宝私钥失败: %w", err)
	}

	code := proof
	logger.Infof("[Alipay] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 发送请求
	bodyStr, err := p.sendOAuthRequest(ctx, code, alipayAppID, privateKey)
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

// Resolve 小程序不支持通过 principal 本地查找
func (*MPProvider) Resolve(_ context.Context, _ string) (*models.TUserInfo, error) {
	return nil, errors.New("alipay mp provider does not support resolve")
}

// FetchAdditionalInfo 补充获取用户信息
func (*MPProvider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	logger.Warnf("[Alipay] 支付宝获取 %s 暂未实现", infoType)
	return nil, fmt.Errorf("alipay does not support fetching %s yet", infoType)
}

// Exchange 用 auth_user 授权码换取手机号
// proof: my.getAuthCode({scopes: ['auth_user']}) 返回的 auth_code
func (p *MPProvider) Exchange(ctx context.Context, proof string, _ ...any) (*idp.ExchangeResult, error) {
	if proof == "" {
		return nil, errors.New("auth code is required")
	}

	appID := idp.AppIDFromContext(ctx)
	alipayAppID, alipaySecret, err := p.resolver.ResolveIDPKey(ctx, appID, idp.TypeAlipayMP)
	if err != nil {
		return nil, fmt.Errorf("解析支付宝小程序 IDP 密钥失败: %w", err)
	}

	privateKey, err := parsePrivateKey(alipaySecret)
	if err != nil {
		return nil, fmt.Errorf("解析支付宝私钥失败: %w", err)
	}

	accessToken, err := p.getAccessToken(ctx, proof, alipayAppID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("换取 access_token 失败: %w", err)
	}

	phone, err := p.getUserPhone(ctx, accessToken, alipayAppID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("获取手机号失败: %w", err)
	}

	return &idp.ExchangeResult{Value: phone}, nil
}

// Prepare 准备前端所需的公开配置（密钥动态解析，此处不含 Identifier）
func (p *MPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: "almp",
	}
}

// sendOAuthRequest 发送 OAuth 请求
func (p *MPProvider) sendOAuthRequest(ctx context.Context, code, alipayAppID string, privateKey *rsa.PrivateKey) (string, error) {
	reqParams := p.buildRequestParams(code, alipayAppID)

	signContent := buildSignContent(reqParams)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)

	sign, err := signWithRSA2(privateKey, signContent)
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
	logger.Debugf("[Alipay] 响应长度: %d", len(bodyBytes))
	return bodyStr, nil
}

// buildRequestParams 构建请求参数
func (p *MPProvider) buildRequestParams(code, alipayAppID string) map[string]string {
	return map[string]string{
		"app_id":     alipayAppID,
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
func (p *MPProvider) parseUserID(bodyStr string) (*models.TUserInfo, error) {
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

	return &models.TUserInfo{
		TOpenID: userID,
		RawData: fmt.Sprintf(`{"openid":"%s"}`, userID),
	}, nil
}

// getAccessToken 用授权码换取 access_token
func (p *MPProvider) getAccessToken(ctx context.Context, code, alipayAppID string, privateKey *rsa.PrivateKey) (string, error) {
	bodyStr, err := p.sendOAuthRequest(ctx, code, alipayAppID, privateKey)
	if err != nil {
		return "", err
	}
	if err := p.checkErrorResponse(bodyStr); err != nil {
		return "", err
	}

	accessToken := gjson.Get(bodyStr, "alipay_system_oauth_token_response.access_token").String()
	if accessToken == "" {
		return "", errors.New("响应中缺少 access_token")
	}
	return accessToken, nil
}

// getUserPhone 调用 alipay.user.info.share 获取用户手机号
func (p *MPProvider) getUserPhone(ctx context.Context, accessToken, alipayAppID string, privateKey *rsa.PrivateKey) (string, error) {
	reqParams := map[string]string{
		"app_id":     alipayAppID,
		"method":     "alipay.user.info.share",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
		"version":    "1.0",
		"auth_token": accessToken,
	}

	signContent := buildSignContent(reqParams)
	sign, err := signWithRSA2(privateKey, signContent)
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}
	reqParams["sign"] = sign

	form := url.Values{}
	for k, v := range reqParams {
		form.Add(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[Alipay] close response body failed: %v", closeErr)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)

	errCode := gjson.Get(bodyStr, "alipay_user_info_share_response.code").String()
	if errCode != "" && errCode != "10000" {
		errMsg := gjson.Get(bodyStr, "alipay_user_info_share_response.msg").String()
		subMsg := gjson.Get(bodyStr, "alipay_user_info_share_response.sub_msg").String()
		logger.Errorf("[Alipay] 获取用户信息失败 - Code: %s, Msg: %s, SubMsg: %s", errCode, errMsg, subMsg)
		return "", fmt.Errorf("获取用户信息失败: %s - %s", errMsg, subMsg)
	}

	phone := gjson.Get(bodyStr, "alipay_user_info_share_response.mobile").String()
	if phone == "" {
		return "", errors.New("用户信息中缺少手机号（可能未授权 auth_user scope）")
	}

	logger.Infof("[Alipay] 获取手机号成功 - Phone: %s", maskPhone(phone))
	return phone, nil
}

func maskPhone(phone string) string {
	if len(phone) >= 7 {
		return phone[:3] + "***" + phone[len(phone)-4:]
	}
	return "***"
}
