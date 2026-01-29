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

	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/auth/types"
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
	cfg := config.Auth()
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
func (p *MPProvider) Exchange(ctx context.Context, params ...any) (*idp.ExchangeResult, error) {
	if len(params) < 1 {
		return nil, errors.New("code is required")
	}
	code, ok := params[0].(string)
	if !ok {
		return nil, errors.New("code must be a string")
	}

	if p.appID == "" || p.privateKey == nil {
		return nil, errors.New("支付宝小程序 IdP 未配置")
	}

	logger.Infof("[Alipay] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 构建请求参数
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	reqParams := map[string]string{
		"app_id":     p.appID,
		"method":     "alipay.system.oauth.token",
		"format":     "JSON",
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  timestamp,
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       code,
	}

	// 构建签名字符串
	signContent := buildSignContent(reqParams)
	logger.Debugf("[Alipay] 待签名字符串: %s", signContent)
	sign, err := signWithRSA2(p.privateKey, signContent)
	if err != nil {
		logger.Errorf("[Alipay] 签名失败: %v", err)
		return nil, fmt.Errorf("签名失败: %w", err)
	}
	reqParams["sign"] = sign

	// 构建 POST 请求
	form := url.Values{}
	for k, v := range reqParams {
		form.Add(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://openapi.alipay.com/gateway.do", strings.NewReader(form.Encode()))
	if err != nil {
		logger.Errorf("[Alipay] 构建请求失败: %v", err)
		return nil, fmt.Errorf("构建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("[Alipay] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Alipay] close response body failed: %v", err)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[Alipay] 读取响应失败: %v", err)
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	bodyStr := string(bodyBytes)
	logger.Infof("[Alipay] 响应: %s", bodyStr)

	// 检查是否有错误响应
	errorCode := gjson.Get(bodyStr, "error_response.code").String()
	if errorCode != "" {
		errorMsg := gjson.Get(bodyStr, "error_response.msg").String()
		subMsg := gjson.Get(bodyStr, "error_response.sub_msg").String()
		logger.Errorf("[Alipay] 登录失败 - Code: %s, Msg: %s, SubMsg: %s", errorCode, errorMsg, subMsg)
		return nil, fmt.Errorf("登录失败: %s - %s", errorMsg, subMsg)
	}

	// 验证响应签名
	if p.publicKey != nil {
		respSign := gjson.Get(bodyStr, "sign").String()
		if respSign != "" {
			responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
			if responseNode.Exists() {
				responseRaw := responseNode.Raw
				err = verifySign(p.publicKey, responseRaw, respSign)
				if err != nil {
					logger.Errorf("[Alipay] 响应签名验证失败: %v", err)
					return nil, fmt.Errorf("响应签名验证失败: %w", err)
				}
				logger.Infof("[Alipay] 响应签名验证成功")
			}
		}
	}

	// 解析成功响应
	responseNode := gjson.Get(bodyStr, "alipay_system_oauth_token_response")
	if !responseNode.Exists() {
		logger.Errorf("[Alipay] 响应中缺少 alipay_system_oauth_token_response")
		return nil, errors.New("响应中缺少 alipay_system_oauth_token_response")
	}

	// 提取用户ID（使用 open_id 字段）
	userID := gjson.Get(bodyStr, "alipay_system_oauth_token_response.open_id").String()
	if userID == "" {
		logger.Errorf("[Alipay] 响应中缺少 open_id 字段")
		return nil, errors.New("响应中缺少 open_id 字段")
	}

	logger.Infof("[Alipay] 登录成功 - UserID: %s", userID)

	return &idp.ExchangeResult{
		ProviderID: userID,
		RawData:    fmt.Sprintf(`{"openid":"%s"}`, userID),
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (*MPProvider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	logger.Warnf("[Alipay] 支付宝获取 %s 暂未实现", infoType)
	return nil, fmt.Errorf("alipay does not support fetching %s yet", infoType)
}

// ToPublicConfig 转换为前端可用的公开配置
func (p *MPProvider) ToPublicConfig() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		ID:           "alipay-mp",
		ProviderType: idp.TypeAlipayMP,
		Name:         "支付宝小程序",
		ClientID:     p.appID,
	}
}
