package tt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/tidwall/gjson"

	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MPProvider 抖音小程序 Provider
type MPProvider struct {
	resolver idp.KeyResolver
}

// NewMPProvider 创建抖音小程序 Provider
func NewMPProvider(resolver idp.KeyResolver) *MPProvider {
	return &MPProvider{
		resolver: resolver,
	}
}

// Type 返回 IDP 类型
func (p *MPProvider) Type() string {
	return idp.TypeTTMP
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

	ttAppID, ttAppSecret, err := p.resolver.ResolveIDPKey(ctx, appID, idp.TypeTTMP)
	if err != nil {
		return nil, fmt.Errorf("解析抖音小程序 IDP 密钥失败: %w", err)
	}

	code := proof
	logger.Infof("[TT] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 发送请求
	bodyBytes, err := p.sendSessionRequest(ctx, code, ttAppID, ttAppSecret)
	if err != nil {
		return nil, err
	}

	// 检查错误响应
	if err := p.checkError(bodyBytes); err != nil {
		return nil, err
	}

	// 解析用户信息
	return p.parseUserInfo(bodyBytes)
}

// Resolve 小程序不支持通过 principal 本地查找
func (*MPProvider) Resolve(_ context.Context, _ string) (*models.TUserInfo, error) {
	return nil, errors.New("tt mp provider does not support resolve")
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

// Exchange 用外部凭证换取结果（小程序手机号授权 code → 手机号）
// proof: 手机号授权 code
func (p *MPProvider) Exchange(ctx context.Context, proof string, _ ...any) (*idp.ExchangeResult, error) {
	if proof == "" {
		return nil, errors.New("phone code is required")
	}
	phone, err := p.getPhoneNumber(ctx, proof)
	if err != nil {
		return nil, err
	}
	return &idp.ExchangeResult{
		Value: phone,
	}, nil
}

// Prepare 准备前端所需的公开配置（密钥动态解析，此处不含 Identifier）
func (p *MPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: "ttmp",
	}
}

// sendSessionRequest 发送会话请求
func (p *MPProvider) sendSessionRequest(ctx context.Context, code, ttAppID, ttAppSecret string) ([]byte, error) {
	reqBody := map[string]string{
		"appid":  ttAppID,
		"secret": ttAppSecret,
		"code":   code,
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		logger.Errorf("[TT] 构建请求体失败: %v", err)
		return nil, fmt.Errorf("构建请求体失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://developer.toutiao.com/api/apps/v2/jscode2session",
		bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		logger.Errorf("[TT] 创建请求失败: %v", err)
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Errorf("[TT] 请求接口失败: %v", err)
		return nil, fmt.Errorf("请求接口失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[TT] close response body failed: %v", closeErr)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("[TT] 读取响应失败: %v", err)
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("[TT] API 返回非 200 状态码: %d, 响应: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("API 请求失败: HTTP %d", resp.StatusCode)
	}

	logger.Debugf("[TT] API 响应长度: %d", len(bodyBytes))
	return bodyBytes, nil
}

// checkError 检查错误响应
func (p *MPProvider) checkError(bodyBytes []byte) error {
	errNo := gjson.GetBytes(bodyBytes, "err_no").Int()
	if errNo == 0 {
		return nil
	}
	errTips := gjson.GetBytes(bodyBytes, "err_tips").String()
	logger.Errorf("[TT] 登录失败 - ErrNo: %d, ErrTips: %s", errNo, errTips)
	return fmt.Errorf("登录失败: %s", errTips)
}

// parseUserInfo 解析用户信息
func (p *MPProvider) parseUserInfo(bodyBytes []byte) (*models.TUserInfo, error) {
	dataRaw := gjson.GetBytes(bodyBytes, "data")
	if !dataRaw.Exists() || dataRaw.Raw == "null" {
		logger.Errorf("[TT] 响应 data 字段为空或 null")
		return nil, errors.New("响应 data 字段为空")
	}

	openID := gjson.GetBytes(bodyBytes, "data.openid").String()

	if openID == "" {
		logger.Errorf("[TT] data 中缺少 openid")
		return nil, errors.New("data 中缺少 openid")
	}

	logger.Infof("[TT] 登录成功 - OpenID: %s", openID)

	return &models.TUserInfo{
		TOpenID: openID,
		RawData: fmt.Sprintf(`{"openid":"%s"}`, openID),
	}, nil
}

// getPhoneNumber 获取抖音手机号
// 新版 API：code → RSA 加密的密文 → 用应用私钥解密 → phoneNumber
func (p *MPProvider) getPhoneNumber(ctx context.Context, code string) (string, error) {
	appID := idp.AppIDFromContext(ctx)
	ttAppID, ttSecret, err := p.resolver.ResolveIDPKey(ctx, appID, idp.TypeTTMP)
	if err != nil {
		return "", fmt.Errorf("解析抖音小程序 IDP 密钥失败: %w", err)
	}

	// ttSecret 中存储的是 RSA 私钥（base64 编码）
	privateKey, err := parsePKCS1PrivateKey(ttSecret)
	if err != nil {
		return "", fmt.Errorf("解析 TT 应用私钥失败: %w", err)
	}

	clientToken, err := p.getClientToken(ctx, ttAppID, ttSecret)
	if err != nil {
		return "", err
	}

	reqBody, _ := json.Marshal(map[string]string{"code": code})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://open.douyin.com/api/apps/v1/get_phonenumber_info/",
		bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("access-token", clientToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Errorf("[TT] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求 TT 接口失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[TT] close phone response body failed: %v", closeErr)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 TT 响应失败: %w", err)
	}

	errNo := gjson.GetBytes(bodyBytes, "err_no").Int()
	if errNo != 0 {
		errMsg := gjson.GetBytes(bodyBytes, "err_msg").String()
		logger.Errorf("[TT] 获取手机号失败 - ErrNo: %d, ErrMsg: %s", errNo, errMsg)
		return "", fmt.Errorf("TT 获取手机号失败: %s", errMsg)
	}

	encryptedData := gjson.GetBytes(bodyBytes, "data").String()
	if encryptedData == "" {
		return "", errors.New("TT 返回的加密数据为空")
	}

	plaintext, err := rsaDecrypt(privateKey, encryptedData)
	if err != nil {
		logger.Errorf("[TT] RSA 解密手机号失败: %v", err)
		return "", fmt.Errorf("RSA 解密失败: %w", err)
	}

	phone := gjson.GetBytes(plaintext, "purePhoneNumber").String()
	if phone == "" {
		phone = gjson.GetBytes(plaintext, "phoneNumber").String()
	}
	if phone == "" {
		return "", errors.New("TT 解密后手机号为空")
	}

	logger.Infof("[TT] 获取手机号成功 - Phone: %s", maskPhone(phone))
	return phone, nil
}

// getClientToken 获取 TT client_token（不需要用户授权的接口凭证）
func (p *MPProvider) getClientToken(ctx context.Context, ttAppID, ttAppSecret string) (string, error) {
	if ttAppID == "" || ttAppSecret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	reqBody, _ := json.Marshal(map[string]string{
		"client_key":    ttAppID,
		"client_secret": ttAppSecret,
		"grant_type":    "client_credential",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://open.douyin.com/oauth/client_token/",
		bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 TT client_token 失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[TT] close client_token response body failed: %v", closeErr)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 TT client_token 响应失败: %w", err)
	}

	accessToken := gjson.GetBytes(bodyBytes, "data.access_token").String()
	if accessToken == "" {
		errDesc := gjson.GetBytes(bodyBytes, "data.description").String()
		return "", fmt.Errorf("获取 TT client_token 失败: %s", errDesc)
	}

	return accessToken, nil
}

// parsePKCS1PrivateKey 解析 PKCS1 格式的 RSA 私钥（base64 编码，无 PEM header/footer）
func parsePKCS1PrivateKey(raw string) (*rsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\n", "")
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.TrimPrefix(raw, "-----BEGIN RSA PRIVATE KEY-----")
	raw = strings.TrimSuffix(raw, "-----END RSA PRIVATE KEY-----")
	raw = strings.TrimSpace(raw)

	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	pk, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS1: %w", err)
	}
	return pk, nil
}

// rsaDecrypt 使用 PKCS1v15 解密 base64 编码的密文
func rsaDecrypt(pk *rsa.PrivateKey, cipherBase64 string) ([]byte, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode cipher: %w", err)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, pk, cipherBytes)
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func maskPhone(phone string) string {
	if len(phone) >= 7 {
		return phone[:3] + "***" + phone[len(phone)-4:]
	}
	return "***"
}
