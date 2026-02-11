package authenticate

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
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
	cache *cache.Manager
}

// NewService 创建认证服务
func NewService(cache *cache.Manager) *Service {
	return &Service{
		cache: cache,
	}
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
	if req.ResponseType != types.ResponseTypeCode {
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

	flow := types.NewAuthFlow(req, time.Duration(config.GetAegisCookieMaxAge())*time.Second, config.GetAegisAuthFlowMaxLifetime())
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
// 验证成功后会更新内存中的过期时间（需要调用方调用 SaveFlow 持久化）
func (s *Service) GetAndValidateFlow(ctx context.Context, flowID string) *types.AuthFlow {
	flow, err := s.GetFlow(ctx, flowID)
	if err != nil {
		logger.Warnf("[Authenticate] 获取 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
		// 创建空 flow 来存储错误
		flow = &types.AuthFlow{ID: flowID}
		flow.Fail(autherrors.NewFlowNotFound("session not found"))
		return flow
	}

	// 检查最大生命周期（绝对过期，不可续期）
	if flow.IsMaxExpired() {
		logger.Warnf("[Authenticate] Flow 已超过最大生命周期 - FlowID: %s, MaxExpiresAt: %v", flowID, flow.MaxExpiresAt)
		flow.Fail(autherrors.NewFlowExpired("session expired"))
		return flow
	}

	if flow.IsExpired() {
		logger.Warnf("[Authenticate] Flow 已过期 - FlowID: %s, ExpiredAt: %v", flowID, flow.ExpiresAt)
		flow.Fail(autherrors.NewFlowExpired("session expired"))
		return flow
	}

	// 验证成功，更新内存中的过期时间（滑动窗口续期，受 MaxExpiresAt 限制）
	// 注意：需要调用方调用 SaveFlow 持久化
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
// 调用方需先完成 flow.SetConnection 设置当前 Connection
// params: 认证参数（proof 等，传递给 Authenticator.Authenticate）
func (s *Service) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	// 1. 验证 flow 状态
	if !flow.CanAuthenticate() {
		return false, autherrors.NewFlowInvalid("flow state does not allow authentication")
	}

	// 2. 从注册表获取认证器
	auth, ok := authenticator.GlobalRegistry().Get(flow.Connection)
	if !ok {
		return false, autherrors.NewInvalidRequestf("unsupported connection: %s", flow.Connection)
	}

	// 3. 执行认证
	success, err := auth.Authenticate(ctx, flow, params...)
	if err != nil {
		return false, err
	}

	logger.Infof("[Authenticate] 认证成功 - FlowID: %s, Connection: %s", flow.ID, flow.Connection)

	return success, nil
}

// GetAvailableConnections 获取可用的 ConnectionsMap
// 按 ConnectionType（idp/vchan/factor）分类，转换为前端公开的 Connection 结构
func (s *Service) GetAvailableConnections(flow *types.AuthFlow) types.ConnectionsMap {
	result := make(types.ConnectionsMap)
	if flow.ConnectionMap == nil {
		return result
	}

	for _, cfg := range flow.ConnectionMap {
		result[cfg.Type] = append(result[cfg.Type], types.NewConnection(cfg))
	}

	return result
}

// ==================== Flow 清理 ====================

// CleanupFlow 处理 flow 清理（登录成功删除，失败保存）
func (s *Service) CleanupFlow(ctx context.Context, flowID string, flow *types.AuthFlow, loginSuccess bool) {
	if loginSuccess {
		if err := s.DeleteFlow(ctx, flowID); err != nil {
			logger.Warnf("[Authenticate] 删除 flow 失败: %v", err)
		}
	} else {
		if err := s.SaveFlow(ctx, flow); err != nil {
			logger.Warnf("[Authenticate] 保存 flow 失败: %v", err)
		}
	}
}

// ==================== 辅助方法 ====================

// setConnections 根据应用 IDP 配置构建 ConnectionMap
// 包含 IDP + 被引用的 Required/Delegated connections，确保 Login 时能追踪所有验证状态
// 合并 Authenticator.Prepare() 基础配置与应用级配置（strategy, delegate, require）
func (s *Service) setConnections(idpConfigs []*models.ApplicationIDPConfig) map[string]*types.ConnectionConfig {
	result := make(map[string]*types.ConnectionConfig, len(idpConfigs))
	referencedSet := make(map[string]bool)

	for _, idpCfg := range idpConfigs {
		cfg := s.buildConnectionConfig(idpCfg)
		if cfg == nil {
			continue
		}
		result[idpCfg.Type] = cfg
		collectReferences(cfg, referencedSet)
	}

	// 将被引用的 Required/Delegated connections 也加入 ConnectionMap
	s.addReferencedConnections(result, referencedSet)
	return result
}

// buildConnectionConfig 构建单个 IDP 的 ConnectionConfig（合并应用级配置）
func (s *Service) buildConnectionConfig(idpCfg *models.ApplicationIDPConfig) *types.ConnectionConfig {
	auth, ok := authenticator.GlobalRegistry().Get(idpCfg.Type)
	if !ok {
		return nil
	}
	cfg := auth.Prepare()
	if cfg == nil {
		return nil
	}
	if list := idpCfg.GetStrategyList(); len(list) > 0 {
		cfg.Strategy = list
	}
	if list := idpCfg.GetDelegateList(); len(list) > 0 {
		cfg.Delegate = list
	}
	if list := idpCfg.GetRequireList(); len(list) > 0 {
		cfg.Require = list
	}
	return cfg
}

// collectReferences 收集 cfg 中被引用的 require/delegate connection 名称
func collectReferences(cfg *types.ConnectionConfig, set map[string]bool) {
	for _, r := range cfg.Require {
		set[r] = true
	}
	for _, d := range cfg.Delegate {
		set[d] = true
	}
}

// addReferencedConnections 将被引用但尚未在 result 中的 connections 加入 ConnectionMap
func (s *Service) addReferencedConnections(result map[string]*types.ConnectionConfig, referencedSet map[string]bool) {
	for conn := range referencedSet {
		if _, exists := result[conn]; exists {
			continue
		}
		if auth, ok := authenticator.GlobalRegistry().Get(conn); ok {
			if cfg := auth.Prepare(); cfg != nil {
				result[conn] = cfg
			}
		}
	}
}
