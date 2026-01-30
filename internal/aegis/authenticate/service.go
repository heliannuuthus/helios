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
	"github.com/heliannuuthus/helios/internal/hermes/models"
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
// 错误信息会存储在返回的 flow.Error 中，调用方通过 flow.HasError() 检查
func (s *Service) CreateFlow(c *gin.Context, req *types.AuthRequest) *types.AuthFlow {
	ctx := c.Request.Context()

	// 从配置获取 Flow 过期时间（秒转为 Duration）
	flowExpiresIn := time.Duration(config.GetAuthCookieMaxAge()) * time.Second

	// 先创建 flow，后续错误都记录在 flow 中
	flow := types.NewAuthFlow(req, flowExpiresIn)

	// 1. 验证 response_type
	if req.ResponseType != "code" {
		flow.Fail(autherrors.NewInvalidRequest("response_type must be 'code'"))
		return flow
	}

	// 2. 获取 Application
	app, err := s.cache.GetApplication(ctx, req.ClientID)
	if err != nil {
		flow.Fail(autherrors.NewClientNotFoundf("application not found: %s", req.ClientID))
		return flow
	}
	flow.Application = app

	// 3. 验证请求来源（应用侧跨域验证）
	if err := validateOrigin(c, app); err != nil {
		flow.Fail(err)
		return flow
	}

	// 4. 验证重定向 URI
	if !app.ValidateRedirectURI(req.RedirectURI) {
		flow.Fail(autherrors.NewInvalidRequest("invalid redirect_uri"))
		return flow
	}

	// 5. 获取 Service
	svc, err := s.cache.GetService(ctx, req.Audience)
	if err != nil {
		flow.Fail(autherrors.NewServiceNotFoundf("service not found: %s", req.Audience))
		return flow
	}
	flow.Service = svc

	// 6. 验证 Application-Service 关系
	hasRelation, err := s.cache.CheckAppServiceRelation(ctx, req.ClientID, req.Audience)
	if err != nil {
		flow.Fail(autherrors.NewServerError("check relation failed"))
		return flow
	}
	if !hasRelation {
		flow.Fail(autherrors.NewAccessDeniedf("application %s has no access to service %s", req.ClientID, req.Audience))
		return flow
	}

	// 7. 获取应用配置的登录方式
	allowedIDPs := app.GetAllowedIDPs()
	if len(allowedIDPs) == 0 {
		flow.Fail(autherrors.NewNoConnectionAvailable(""))
		return flow
	}

	// 8. 构建 ConnectionMap（使用应用配置的 IDP）
	flow.ConnectionMap = s.setConnections(allowedIDPs)

	// 9. 保存到缓存
	if err := s.SaveFlow(ctx, flow); err != nil {
		flow.Fail(autherrors.NewServerError("save flow failed"))
		return flow
	}

	logger.Infof("[Authenticate] 创建认证流程 - FlowID: %s, ClientID: %s", flow.ID, req.ClientID)

	return flow
}

// GetAndValidateFlow 获取并验证 AuthFlow
// 错误信息存储在返回的 flow.Error 中
func (s *Service) GetAndValidateFlow(ctx context.Context, flowID string) *types.AuthFlow {
	flow, err := s.GetFlow(ctx, flowID)
	if err != nil {
		// 创建空 flow 来存储错误
		flow = &types.AuthFlow{ID: flowID}
		flow.Fail(autherrors.NewFlowNotFound("session not found"))
		return flow
	}

	if flow.IsExpired() {
		flow.Fail(autherrors.NewFlowExpired("session expired"))
		return flow
	}

	return flow
}

// GetFlow 获取 AuthFlow
func (s *Service) GetFlow(ctx context.Context, flowID string) (*types.AuthFlow, error) {
	data, err := s.cache.GetAuthFlow(ctx, flowID)
	if err != nil {
		return nil, autherrors.NewFlowNotFound("session not found")
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(data, &flow); err != nil {
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

// GetAvailableConnections 获取可用的 Connection（从 flow.ConnectionMap）
func (s *Service) GetAvailableConnections(flow *types.AuthFlow) []*types.ConnectionConfig {
	if flow.ConnectionMap == nil {
		return nil
	}

	configs := make([]*types.ConnectionConfig, 0, len(flow.ConnectionMap))
	for _, cfg := range flow.ConnectionMap {
		configs = append(configs, cfg)
	}
	return configs
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
	var name string

	switch idpType {
	case idp.TypeWechatMP:
		configPrefix = "idps.wxmp"
		name = "微信小程序"
	case idp.TypeTTMP:
		configPrefix = "idps.tt"
		name = "抖音小程序"
	case idp.TypeAlipayMP:
		configPrefix = "idps.alipay"
		name = "支付宝小程序"
	case idp.TypeWecom:
		configPrefix = "idps.wecom"
		name = "企业微信"
	case idp.TypeGithub:
		configPrefix = "idps.github"
		name = "GitHub"
	case idp.TypeGoogle:
		configPrefix = "idps.google"
		name = "Google"
	default:
		return nil
	}

	authCfg := config.Auth()
	appID := authCfg.GetString(configPrefix + ".appid")
	if appID == "" {
		return nil
	}

	connCfg := &types.ConnectionConfig{
		ID:            idpType,
		ProviderType:  idpType,
		Name:          name,
		ClientID:      appID,
		AllowedScopes: authCfg.GetStringSlice(configPrefix + ".allowed_scopes"),
	}

	// 人机验证配置
	if authCfg.GetBool(configPrefix + ".capture.required") {
		connCfg.Capture = &types.CaptureConfig{
			Required: true,
			Type:     authCfg.GetString(configPrefix + ".capture.type"),
			SiteKey:  authCfg.GetString(configPrefix + ".capture.site_key"),
		}
	}

	return connCfg
}

// validateOrigin 验证请求来源是否允许
// 从 gin.Context 获取 Origin/Referer header，验证是否在应用的允许列表中
func validateOrigin(c *gin.Context, app *models.ApplicationWithKey) *autherrors.AuthError {
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = c.GetHeader("Referer")
	}

	// 没有 Origin 头，跳过验证
	if origin == "" {
		return nil
	}

	// 验证 Origin 是否在允许列表中
	if !app.ValidateOrigin(origin) {
		return autherrors.NewInvalidOriginf("origin %s not allowed for application %s", origin, app.AppID)
	}

	return nil
}
