package tt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MPProvider 抖音小程序 Provider
type MPProvider struct {
	appID     string
	appSecret string
}

// NewMPProvider 创建抖音小程序 Provider
func NewMPProvider() *MPProvider {
	cfg := config.Aegis()
	return &MPProvider{
		appID:     cfg.GetString("idps.tt.appid"),
		appSecret: cfg.GetString("idps.tt.secret"),
	}
}

// Type 返回 IDP 类型
func (p *MPProvider) Type() string {
	return idp.TypeTTMP
}

// Exchange 用授权码换取用户信息
func (p *MPProvider) Exchange(ctx context.Context, params ...any) (*idp.ExchangeResult, error) {
	code, err := p.extractCode(params)
	if err != nil {
		return nil, err
	}

	if err := p.validateConfig(); err != nil {
		return nil, err
	}

	logger.Infof("[TT] 登录请求 - Code: %s...", code[:min(len(code), 10)])

	// 发送请求
	bodyBytes, err := p.sendSessionRequest(ctx, code)
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

// extractCode 提取授权码
func (p *MPProvider) extractCode(params []any) (string, error) {
	if len(params) < 1 {
		return "", errors.New("code is required")
	}
	code, ok := params[0].(string)
	if !ok {
		return "", errors.New("code must be a string")
	}
	return code, nil
}

// validateConfig 验证配置
func (p *MPProvider) validateConfig() error {
	if p.appID == "" || p.appSecret == "" {
		return errors.New("TT 小程序 IdP 未配置")
	}
	return nil
}

// sendSessionRequest 发送会话请求
func (p *MPProvider) sendSessionRequest(ctx context.Context, code string) ([]byte, error) {
	reqBody := map[string]string{
		"appid":  p.appID,
		"secret": p.appSecret,
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

	resp, err := http.DefaultClient.Do(req)
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

	logger.Infof("[TT] API 原始响应: %s", string(bodyBytes))
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
func (p *MPProvider) parseUserInfo(bodyBytes []byte) (*idp.ExchangeResult, error) {
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

	return &idp.ExchangeResult{
		ProviderID: openID,
		RawData:    fmt.Sprintf(`{"openid":"%s"}`, openID),
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
		Connection: "tt",
		Strategy:   []string{"mp"},
	}
}

// getPhoneNumber 获取抖音手机号（内部方法）
func (p *MPProvider) getPhoneNumber(ctx context.Context, code string) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return "", err
	}

	reqURL := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/user/get_phone_number?access_token=%s", accessToken)

	body := fmt.Sprintf(`{"code":"%s"}`, code)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Errorf("[TT] 请求获取手机号接口失败: %v", err)
		return "", fmt.Errorf("请求 TT 接口失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[TT] close phone response body failed: %v", closeErr)
		}
	}()

	var result struct {
		ErrNo   int    `json:"err_no"`
		ErrTips string `json:"err_tips"`
		Data    struct {
			PhoneNumber string `json:"phone_number"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Errorf("[TT] 解析手机号响应失败: %v", err)
		return "", fmt.Errorf("解析 TT 响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		logger.Errorf("[TT] 获取手机号失败 - ErrNo: %d, ErrTips: %s", result.ErrNo, result.ErrTips)
		return "", fmt.Errorf("TT 获取手机号失败: %s", result.ErrTips)
	}

	phone := result.Data.PhoneNumber
	if phone == "" {
		return "", errors.New("TT 返回的手机号为空")
	}

	logger.Infof("[TT] 获取手机号成功 - Phone: %s***%s", phone[:3], phone[len(phone)-4:])
	return phone, nil
}

// getAccessToken 获取 TT access_token
func (p *MPProvider) getAccessToken(ctx context.Context) (string, error) {
	if p.appID == "" || p.appSecret == "" {
		return "", errors.New("TT 小程序配置缺失")
	}

	reqURL := fmt.Sprintf("https://developer.toutiao.com/api/apps/v2/token?appid=%s&secret=%s&grant_type=client_credential", p.appID, p.appSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 TT access_token 失败: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warnf("[TT] close access_token response body failed: %v", closeErr)
		}
	}()

	var result struct {
		ErrNo   int    `json:"err_no"`
		ErrTips string `json:"err_tips"`
		Data    struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析 TT access_token 响应失败: %w", err)
	}

	if result.ErrNo != 0 {
		return "", fmt.Errorf("获取 TT access_token 失败: %s", result.ErrTips)
	}

	return result.Data.AccessToken, nil
}
