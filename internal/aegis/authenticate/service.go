package authenticate

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 认证服务
// 管理 AuthFlow，不连接数据库
type Service struct {
	cache          *cache.Manager
	idpRegistry    *idp.Registry
	authenticators []Authenticator
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache       *cache.Manager
	IDPRegistry *idp.Registry
	EmailSender EmailSender
}

// NewService 创建认证服务
func NewService(cfg *ServiceConfig) *Service {
	s := &Service{
		cache:       cfg.Cache,
		idpRegistry: cfg.IDPRegistry,
	}

	// 注册认证器
	s.authenticators = []Authenticator{
		NewIDPAuthenticator(cfg.IDPRegistry),
		NewEmailAuthenticator(cfg.Cache, cfg.EmailSender),
	}

	return s
}

// ==================== AuthFlow 管理 ====================

// CreateFlow 创建认证流程
// 前置检查错误（参数验证、数据查询等）直接返回 error
// 流程内错误（认证失败等）通过 flow.Error 返回
func (s *Service) CreateFlow(c *gin.Context, req *types.AuthRequest) (*types.AuthFlow, error) {
	ctx := c.Request.Context()

	logger.Debugf("[Authenticate] 开始创建认证流程 - ClientID: %s, Audience: %s, RedirectURI: %s",
		req.ClientID, req.Audience, req.RedirectURI)

	// ==================== 前置检查（直接返回 error）====================

	// 1. 验证 response_type
	if req.ResponseType != "code" {
		logger.Warnf("[Authenticate] 无效的 response_type: %s", req.ResponseType)
		return nil, autherrors.NewInvalidRequest("response_type must be 'code'")
	}

	// 2. 获取 Application
	app, err := s.cache.GetApplication(ctx, req.ClientID)
	if err != nil {
		logger.Errorf("[Authenticate] 获取 Application 失败 - ClientID: %s, Error: %v", req.ClientID, err)
		return nil, autherrors.NewClientNotFoundf("application not found: %s", req.ClientID)
	}

	// 3. 验证重定向 URI
	if !app.ValidateRedirectURI(req.RedirectURI) {
		logger.Warnf("[Authenticate] 无效的重定向 URI - ClientID: %s, RedirectURI: %s, AllowedURIs: %v",
			req.ClientID, req.RedirectURI, app.GetRedirectURIs())
		return nil, autherrors.NewInvalidRequest("invalid redirect_uri")
	}

	// 4. 获取 Service
	svc, err := s.cache.GetService(ctx, req.Audience)
	if err != nil {
		logger.Errorf("[Authenticate] 获取 Service 失败 - Audience: %s, Error: %v", req.Audience, err)
		return nil, autherrors.NewServiceNotFoundf("service not found: %s", req.Audience)
	}

	// 5. 验证 Application-Service 关系
	hasRelation, err := s.cache.CheckAppServiceRelation(ctx, req.ClientID, req.Audience)
	if err != nil {
		logger.Errorf("[Authenticate] 检查 Application-Service 关系失败 - ClientID: %s, Audience: %s, Error: %v",
			req.ClientID, req.Audience, err)
		return nil, autherrors.NewServerError("check relation failed")
	}
	if !hasRelation {
		logger.Warnf("[Authenticate] Application 无权访问 Service - ClientID: %s, Audience: %s",
			req.ClientID, req.Audience)
		return nil, autherrors.NewAccessDeniedf("application %s has no access to service %s", req.ClientID, req.Audience)
	}

	// 6. 获取应用配置的登录方式
	allowedIDPs := app.GetAllowedIDPs()
	if len(allowedIDPs) == 0 {
		logger.Warnf("[Authenticate] 应用未配置登录方式 - ClientID: %s", req.ClientID)
		return nil, autherrors.NewNoConnectionAvailable("")
	}

	// ==================== 创建 Flow ====================

	// 从配置获取 Flow 过期时间（秒转为 Duration）
	flowExpiresIn := time.Duration(config.GetAegisCookieMaxAge()) * time.Second

	// 创建 flow
	flow := types.NewAuthFlow(req, flowExpiresIn)
	flow.Application = app
	flow.Service = svc

	// 7. 构建 ConnectionMap（使用应用配置的 IDP）
	flow.ConnectionMap = s.setConnections(allowedIDPs)

	// 8. 保存到缓存
	if err := s.SaveFlow(ctx, flow); err != nil {
		logger.Errorf("[Authenticate] 保存 Flow 失败 - FlowID: %s, Error: %v", flow.ID, err)
		return nil, autherrors.NewServerError("save flow failed")
	}

	logger.Infof("[Authenticate] 创建认证流程成功 - FlowID: %s, ClientID: %s, Audience: %s",
		flow.ID, req.ClientID, req.Audience)

	return flow, nil
}

// GetAndValidateFlow 获取并验证 AuthFlow
// 错误信息存储在返回的 flow.Error 中
func (s *Service) GetAndValidateFlow(ctx context.Context, flowID string) *types.AuthFlow {
	flow, err := s.GetFlow(ctx, flowID)
	if err != nil {
		logger.Warnf("[Authenticate] 获取 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
		// 创建空 flow 来存储错误
		flow = &types.AuthFlow{ID: flowID}
		flow.Fail(autherrors.NewFlowNotFound("session not found"))
		return flow
	}

	if flow.IsExpired() {
		logger.Warnf("[Authenticate] Flow 已过期 - FlowID: %s, ExpiredAt: %v", flowID, flow.ExpiresAt)
		flow.Fail(autherrors.NewFlowExpired("session expired"))
		return flow
	}

	return flow
}

// GetFlow 获取 AuthFlow
func (s *Service) GetFlow(ctx context.Context, flowID string) (*types.AuthFlow, error) {
	data, err := s.cache.GetAuthFlow(ctx, flowID)
	if err != nil {
		logger.Debugf("[Authenticate] 从缓存获取 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
		return nil, autherrors.NewFlowNotFound("session not found")
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		logger.Errorf("[Authenticate] 反序列化 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
		return nil, fmt.Errorf("unmarshal flow failed: %w", err)
	}

	return &flow, nil
}

// SaveFlow 保存 AuthFlow
func (s *Service) SaveFlow(ctx context.Context, flow *types.AuthFlow) error {
	data, err := json.Marshal(flow)
	if err != nil {
		return fmt.Errorf("marshal flow failed: %w", err)
	}

	return s.cache.SaveAuthFlow(ctx, flow.ID, data)
}

// DeleteFlow 删除 AuthFlow（设置短 TTL）
func (s *Service) DeleteFlow(ctx context.Context, flowID string) error {
	return s.cache.DeleteAuthFlow(ctx, flowID)
}

// ==================== 认证 ====================

// Authenticate 执行认证
func (s *Service) Authenticate(ctx context.Context, flow *types.AuthFlow, connection string, data map[string]any) (*AuthResult, error) {
	// 1. 验证 flow 状态
	if !flow.CanAuthenticate() {
		return nil, autherrors.NewFlowInvalid("flow state does not allow authentication")
	}

	// 2. 验证 connection 是否在 ConnectionMap 中
	if _, ok := flow.ConnectionMap[connection]; !ok {
		return nil, autherrors.NewInvalidRequest("connection not found in flow")
	}

	// 3. 选择认证器
	var authenticator Authenticator
	for _, auth := range s.authenticators {
		if auth.Supports(connection) {
			authenticator = auth
			break
		}
	}
	if authenticator == nil {
		return nil, autherrors.NewInvalidRequest("unsupported authentication type")
	}

	// 4. 执行认证
	result, err := authenticator.Authenticate(ctx, connection, data)
	if err != nil {
		return nil, err
	}

	logger.Infof("[Authenticate] 认证成功 - FlowID: %s, Connection: %s, ProviderID: %s", flow.ID, connection, result.ProviderID)

	return result, nil
}

// GetAvailableConnections 获取可用的 ConnectionsMap
func (s *Service) GetAvailableConnections(flow *types.AuthFlow) *types.ConnectionsMap {
	if flow.ConnectionMap == nil {
		return nil
	}

	result := &types.ConnectionsMap{
		IDP:   make([]*types.ConnectionConfig, 0),
		VChan: make([]*types.VChanConfig, 0),
		MFA:   make([]string, 0),
	}

	// 添加 IDP connections
	for _, cfg := range flow.ConnectionMap {
		result.IDP = append(result.IDP, cfg)
	}

	// 添加 captcha vchan（如果配置了）
	captchaCfg := s.getCaptchaConfig()
	if captchaCfg != nil {
		result.VChan = append(result.VChan, captchaCfg)
	}

	// 添加 MFA 列表
	result.MFA = s.getAvailableMFAs()

	return result
}

// getCaptchaConfig 获取 captcha 配置
func (s *Service) getCaptchaConfig() *types.VChanConfig {
	authCfg := config.Aegis()
	if !authCfg.GetBool("captcha.enabled") {
		return nil
	}

	return &types.VChanConfig{
		Connection: "captcha",
		Strategy:   authCfg.GetString("captcha.provider"), // turnstile, recaptcha 等
		Identifier: authCfg.GetString("captcha.site-key"), // 前端需要的 site-key
	}
}

// getAvailableMFAs 获取可用的 MFA 列表
func (s *Service) getAvailableMFAs() []string {
	authCfg := config.Aegis()
	mfas := make([]string, 0)

	if authCfg.GetBool("mfa.email-otp.enabled") {
		mfas = append(mfas, "email-otp")
	}
	if authCfg.GetBool("mfa.tg-otp.enabled") {
		mfas = append(mfas, "tg-otp")
	}
	if authCfg.GetBool("mfa.totp.enabled") {
		mfas = append(mfas, "totp")
	}

	return mfas
}

// SendEmailCode 发送邮箱验证码
func (s *Service) SendEmailCode(ctx context.Context, email string) error {
	for _, auth := range s.authenticators {
		if emailAuth, ok := auth.(*EmailAuthenticator); ok {
			return emailAuth.SendCode(ctx, email)
		}
	}
	return autherrors.NewServerError("email authenticator not configured")
}

// ==================== 辅助方法 ====================

// setConnections 根据应用配置的 IDP 列表构建 ConnectionMap
func (s *Service) setConnections(allowedIDPs []string) map[string]*types.ConnectionConfig {
	connectionMap := make(map[string]*types.ConnectionConfig)

	for _, idpType := range allowedIDPs {
		// 检查 IDP 是否在 Registry 中注册
		if idpType != "email" && !s.idpRegistry.Has(idpType) {
			logger.Warnf("[Authenticate] IDP %s not registered in registry", idpType)
			continue
		}

		cfg := s.getConnectionConfig(idpType)
		if cfg != nil {
			connectionMap[idpType] = cfg
		}
	}

	return connectionMap
}

// getConnectionConfig 获取 Connection 配置
func (s *Service) getConnectionConfig(idpType string) *types.ConnectionConfig {
	var configPrefix string
	var connection string
	var strategy []string

	switch idpType {
	case idp.TypeWechatMP:
		configPrefix = "idps.wxmp"
		connection = "wechat"
		strategy = []string{"mp"}
	case idp.TypeTTMP:
		configPrefix = "idps.tt"
		connection = "tt"
		strategy = []string{"mp"}
	case idp.TypeAlipayMP:
		configPrefix = "idps.alipay"
		connection = "alipay"
		strategy = []string{"mp"}
	case idp.TypeWecom:
		configPrefix = "idps.wecom"
		connection = "wecom"
		strategy = []string{"oauth"}
	case idp.TypeGithub:
		return s.getGithubConnectionConfig()
	case idp.TypeGoogle:
		return s.getGoogleConnectionConfig()
	case "email":
		return s.getEmailConnectionConfig()
	case "user":
		return s.getUserConnectionConfig()
	case "oper":
		return s.getOperConnectionConfig()
	default:
		return nil
	}

	authCfg := config.Aegis()
	appID := authCfg.GetString(configPrefix + ".appid")
	if appID == "" {
		return nil
	}

	connCfg := &types.ConnectionConfig{
		Connection: connection,
		Strategy:   strategy,
	}

	// 检查是否需要 captcha
	if authCfg.GetBool("captcha.enabled") {
		connCfg.Require = &types.RequireConfig{
			VChan: []string{"captcha"},
		}
	}

	return connCfg
}

// getUserConnectionConfig 获取 user 身份配置
func (s *Service) getUserConnectionConfig() *types.ConnectionConfig {
	authCfg := config.Aegis()

	cfg := &types.ConnectionConfig{
		Connection: "user",
		Strategy:   []string{},
	}

	// 检查是否需要 captcha
	if authCfg.GetBool("captcha.enabled") {
		cfg.Require = &types.RequireConfig{
			VChan: []string{"captcha"},
		}
	}

	// 设置 delegate MFA
	delegateMFAs := make([]string, 0)
	if authCfg.GetBool("mfa.email-otp.enabled") {
		delegateMFAs = append(delegateMFAs, "email-otp")
	}
	if len(delegateMFAs) > 0 {
		cfg.Delegate = &types.DelegateConfig{
			MFA: delegateMFAs,
		}
	}

	return cfg
}

// getOperConnectionConfig 获取 oper（运营）身份配置
func (s *Service) getOperConnectionConfig() *types.ConnectionConfig {
	authCfg := config.Aegis()

	cfg := &types.ConnectionConfig{
		Connection: "oper",
		Strategy:   []string{},
	}

	// 检查是否需要 captcha
	if authCfg.GetBool("captcha.enabled") {
		cfg.Require = &types.RequireConfig{
			VChan: []string{"captcha"},
		}
	}

	// 设置 delegate MFA（oper 可能支持更多 MFA）
	delegateMFAs := make([]string, 0)
	if authCfg.GetBool("mfa.email-otp.enabled") {
		delegateMFAs = append(delegateMFAs, "email-otp")
	}
	if authCfg.GetBool("mfa.totp.enabled") {
		delegateMFAs = append(delegateMFAs, "totp")
	}
	if len(delegateMFAs) > 0 {
		cfg.Delegate = &types.DelegateConfig{
			MFA: delegateMFAs,
		}
	}

	return cfg
}

// getGithubConnectionConfig 获取 GitHub OAuth 配置
func (s *Service) getGithubConnectionConfig() *types.ConnectionConfig {
	authCfg := config.Aegis()

	clientID := authCfg.GetString("idps.github.client-id")
	if clientID == "" {
		return nil
	}

	return &types.ConnectionConfig{
		Connection: "github",
		Strategy:   []string{"oauth"},
		OAuth: &types.OAuthConfig{
			ClientID:     clientID,
			AuthorizeURL: "https://github.com/login/oauth/authorize",
			Scope:        "read:user user:email",
		},
	}
}

// getGoogleConnectionConfig 获取 Google OAuth 配置
func (s *Service) getGoogleConnectionConfig() *types.ConnectionConfig {
	authCfg := config.Aegis()

	clientID := authCfg.GetString("idps.google.client-id")
	if clientID == "" {
		return nil
	}

	return &types.ConnectionConfig{
		Connection: "google",
		Strategy:   []string{"oauth"},
		OAuth: &types.OAuthConfig{
			ClientID:     clientID,
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			Scope:        "openid email profile",
		},
	}
}

func (s *Service) getEmailConnectionConfig() *types.ConnectionConfig {
	authCfg := config.Aegis()

	cfg := &types.ConnectionConfig{
		Connection: "email",
		Strategy:   []string{"otp"}, // email 使用 OTP 验证
	}

	// 检查是否需要 captcha
	if authCfg.GetBool("captcha.enabled") {
		cfg.Require = &types.RequireConfig{
			VChan: []string{"captcha"},
		}
	}

	return cfg
}
