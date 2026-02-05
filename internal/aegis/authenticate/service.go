package authenticate

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 认证服务
type Service struct {
	cache          *cache.Manager
	idpRegistry    *idp.Registry
	authenticators []Authenticator
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache       *cache.Manager
	IDPRegistry *idp.Registry
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
	}

	return s
}

// ==================== AuthFlow 管理 ====================

// CreateFlow 创建认证流程
// 前置检查错误（参数验证、数据查询等）直接返回 error
// 流程内错误（认证失败等）通过 flow.Error 返回
func (s *Service) CreateFlow(c *gin.Context, req *types.AuthRequest) (*types.AuthFlow, error) {
	ctx := c.Request.Context()

	logger.Infof("[Authenticate] 开始创建认证流程 - ClientID: %s, Audience: %s, RedirectURI: %s",
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

	// 6. 获取应用 IDP 配置并构建 ConnectionMap
	idpConfigs, err := s.cache.GetApplicationIDPConfigs(ctx, req.ClientID)
	if err != nil {
		logger.Errorf("[Authenticate] 查询应用 IDP 配置失败 - ClientID: %s, Error: %v", req.ClientID, err)
		return nil, autherrors.NewServerError("query idp configs failed")
	}
	if len(idpConfigs) == 0 {
		logger.Warnf("[Authenticate] 应用未配置登录方式 - ClientID: %s", req.ClientID)
		return nil, autherrors.NewNoConnectionAvailable("")
	}

	// ==================== 创建 Flow ====================

	flow := types.NewAuthFlow(req, time.Duration(config.GetAegisCookieMaxAge())*time.Second)
	flow.Application = app
	flow.Service = svc
	flow.ConnectionMap = s.setConnections(idpConfigs)

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
// 验证成功后会更新内存中的过期时间（需要调用方在适当时机调用 SaveFlow 持久化）
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

	// 验证成功，更新内存中的过期时间（续期）
	// 注意：需要调用方在流程结束时调用 SaveFlow 持久化
	s.RenewFlow(flow)

	return flow
}

// RenewFlow 续期 AuthFlow（仅更新内存，需调用 SaveFlow 持久化）
func (s *Service) RenewFlow(flow *types.AuthFlow) {
	ttl := time.Duration(config.GetAegisCookieMaxAge()) * time.Second
	flow.Renew(ttl)
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
		return nil, autherrors.NewServerErrorf("unmarshal flow failed: %v", err)
	}

	return &flow, nil
}

// SaveFlow 保存 AuthFlow
func (s *Service) SaveFlow(ctx context.Context, flow *types.AuthFlow) error {
	data, err := json.Marshal(flow)
	if err != nil {
		return autherrors.NewServerErrorf("marshal flow failed: %v", err)
	}

	return s.cache.SaveAuthFlow(ctx, flow.ID, data)
}

// DeleteFlow 删除 AuthFlow（设置短 TTL）
func (s *Service) DeleteFlow(ctx context.Context, flowID string) error {
	return s.cache.DeleteAuthFlow(ctx, flowID)
}

// ==================== 认证 ====================

// Authenticate 执行认证
// connection: IDP 类型（如 github, google, user, oper）
// proof: 认证凭证（OAuth code / password / OTP code）
// params: 额外参数（如 identifier）
func (s *Service) Authenticate(ctx context.Context, flow *types.AuthFlow, connection string, proof string, params ...any) (*AuthResult, error) {
	// 1. 验证 flow 状态
	if !flow.CanAuthenticate() {
		return nil, autherrors.NewFlowInvalid("flow state does not allow authentication")
	}

	// 2. 获取 ConnectionConfig
	connCfg, ok := flow.ConnectionMap[connection]
	if !ok {
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
	result, err := authenticator.Authenticate(ctx, connCfg, proof, params...)
	if err != nil {
		return nil, err
	}

	logger.Infof("[Authenticate] 认证成功 - FlowID: %s, Connection: %s, ProviderID: %s", flow.ID, connection, result.ProviderID)

	return result, nil
}

// GetAvailableConnections 获取可用的 ConnectionsMap
// 组装三部分数据：
// 1. IDP - 身份提供商（github, google, user, oper, wechat:mp...）
// 2. VChan - 验证渠道/前置验证（captcha:turnstile...）
// 3. MFA - 多因素认证（email_otp, totp, webauthn...），从 IDP 的 delegate 配置中派生
func (s *Service) GetAvailableConnections(flow *types.AuthFlow) *types.ConnectionsMap {
	if flow.ConnectionMap == nil {
		return nil
	}

	result := &types.ConnectionsMap{
		IDP:   make([]*types.ConnectionConfig, 0),
		VChan: make([]*types.ConnectionConfig, 0),
		MFA:   make([]*types.ConnectionConfig, 0),
	}

	// 收集引用的 MFA 和 VChan（去重）
	mfaSet := make(map[string]bool)
	vchanSet := make(map[string]bool)

	// 添加 IDP connections，同时收集 delegate 和 require
	for _, cfg := range flow.ConnectionMap {
		result.IDP = append(result.IDP, cfg)

		// 从 delegate 中收集 MFA（如 email_otp, totp, webauthn）
		for _, mfa := range cfg.Delegate {
			mfaSet[mfa] = true
		}
		// 从 require 中收集 VChan（如 captcha）
		for _, req := range cfg.Require {
			vchanSet[req] = true
		}
	}

	// 构建 VChan 配置（前置验证渠道）
	result.VChan = s.buildVChanConfigs(vchanSet)

	// 构建 MFA 配置（多因素认证）
	result.MFA = s.buildMFAConfigs(mfaSet)

	return result
}

// buildVChanConfigs 根据 VChan 类型集合构建验证渠道配置列表
// 只返回系统实际启用的 VChan（如 captcha）
func (s *Service) buildVChanConfigs(vchanSet map[string]bool) []*types.ConnectionConfig {
	authCfg := config.Aegis()
	vchans := make([]*types.ConnectionConfig, 0)

	// Captcha（人机验证）
	if vchanSet["captcha"] && authCfg.GetBool("captcha.enabled") {
		provider := authCfg.GetString("captcha.provider")
		vchans = append(vchans, &types.ConnectionConfig{
			Connection: "captcha:" + provider,
			Identifier: authCfg.GetString("captcha.site-key"),
		})
	}

	return vchans
}

// buildMFAConfigs 根据 MFA 类型集合构建 MFA 配置列表
// 只返回系统实际启用的 MFA
func (s *Service) buildMFAConfigs(mfaSet map[string]bool) []*types.ConnectionConfig {
	authCfg := config.Aegis()
	mfas := make([]*types.ConnectionConfig, 0)

	// Email OTP
	if mfaSet["email_otp"] && authCfg.GetBool("mfa.email-otp.enabled") {
		mfas = append(mfas, &types.ConnectionConfig{
			Connection: "email_otp",
		})
	}

	// Telegram OTP
	if mfaSet["tg_otp"] && authCfg.GetBool("mfa.tg-otp.enabled") {
		mfas = append(mfas, &types.ConnectionConfig{
			Connection: "tg_otp",
		})
	}

	// TOTP
	if mfaSet["totp"] && authCfg.GetBool("mfa.totp.enabled") {
		mfas = append(mfas, &types.ConnectionConfig{
			Connection: "totp",
		})
	}

	// WebAuthn
	if mfaSet["webauthn"] && authCfg.GetBool("mfa.webauthn.enabled") {
		cfg := &types.ConnectionConfig{
			Connection: "webauthn",
		}
		if rpID := authCfg.GetString("mfa.webauthn.rp-id"); rpID != "" {
			cfg.Identifier = rpID
		}
		mfas = append(mfas, cfg)
	}

	// Passkey（和 WebAuthn 共用底层但作为独立选项）
	if mfaSet["passkey"] && authCfg.GetBool("mfa.passkey.enabled") {
		cfg := &types.ConnectionConfig{
			Connection: "passkey",
		}
		if rpID := authCfg.GetString("mfa.webauthn.rp-id"); rpID != "" {
			cfg.Identifier = rpID
		}
		mfas = append(mfas, cfg)
	}

	return mfas
}

// ==================== 辅助方法 ====================

// setConnections 根据应用 IDP 配置构建 ConnectionMap
// 合并 Provider.Prepare() 基础配置与应用级配置（strategy, delegate, require）
func (s *Service) setConnections(idpConfigs []*models.ApplicationIDPConfig) map[string]*types.ConnectionConfig {
	result := make(map[string]*types.ConnectionConfig, len(idpConfigs))

	for _, idpCfg := range idpConfigs {
		// 获取 Provider 基础配置，未注册的 Provider 跳过
		provider, ok := s.idpRegistry.Get(idpCfg.Type)
		if !ok {
			continue
		}
		cfg := provider.Prepare()

		if cfg == nil {
			continue
		}

		// 应用级配置覆盖
		if list := idpCfg.GetStrategyList(); len(list) > 0 {
			cfg.Strategy = list
		}
		if list := idpCfg.GetDelegateList(); len(list) > 0 {
			cfg.Delegate = list
		}
		if list := idpCfg.GetRequireList(); len(list) > 0 {
			cfg.Require = list
		}

		result[idpCfg.Type] = cfg
	}

	return result
}
