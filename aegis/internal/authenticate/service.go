package authenticate

import (
	"context"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/aegis/config"
	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/accessctl"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/models"
)

// Service 认证服务
type Service struct {
	cache *cache.Manager
	ac    *accessctl.Manager
}

// NewService 创建认证服务
func NewService(cache *cache.Manager, ac *accessctl.Manager) *Service {
	return &Service{
		cache: cache,
		ac:    ac,
	}
}

// ==================== AuthFlow 管理 ====================

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
	ttl := time.Duration(config.GetCookieMaxAge()) * time.Second
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

// ==================== 认证 ====================

// Authenticate 执行认证
// 调用方需先完成 flow.SetConnection 设置当前 Connection
// params 约定顺序：proof, principal, strategy
// remoteIP 通过 context 传递（ctxutil.WithRemoteIP）
//
// Strike 后置：仅在认证失败后计数，达阈值时返回 TooManyRequests error（429 + retry_after）
func (s *Service) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	if !flow.CanAuthenticate() {
		return false, autherrors.NewFlowInvalid("flow state does not allow authentication")
	}

	auth, ok := authenticator.GlobalRegistry().Get(flow.Connection)
	if !ok {
		return false, autherrors.NewInvalidRequestf("unsupported connection: %s", flow.Connection)
	}

	success, err := auth.Authenticate(ctx, flow, params...)
	if err != nil {
		return false, err
	}
	if success {
		logger.Infof("[Authenticate] 认证成功 - FlowID: %s, Connection: %s", flow.ID, flow.Connection)
		return true, nil
	}

	principal := extractStringParam(params, 1)
	policy := buildACPolicy(flow, principal)
	if action, retryAfter := s.ac.Strike(ctx, policy); action == accessctl.ACRateLimited {
		logger.Warnf("[Authenticate] 认证失败且频率达阈值，限流 - FlowID: %s, RetryAfter: %ds", flow.ID, retryAfter)
		return false, autherrors.NewTooManyRequests(retryAfter)
	}

	return false, nil
}

// ==================== 辅助方法 ====================

// SetConnections 根据应用 IDP 配置构建 ConnectionMap
// 包含 IDP + 被引用的 Required/Delegated connections，确保 Login 时能追踪所有验证状态
// 合并 Authenticator.Prepare() 基础配置与应用级配置（strategy, delegate, require）
func (s *Service) SetConnections(idpConfigs []*models.ApplicationIDPConfig) map[string]*types.ConnectionConfig {
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
	return cfg
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

// buildACPolicy 构建验证频率计数策略
// Key 维度：rl:login:{audience}:{connection}:{principal}
func buildACPolicy(flow *types.AuthFlow, principal string) *accessctl.Policy {
	audience := ""
	if flow.Request != nil {
		audience = flow.Request.Audience
	}
	return accessctl.NewPolicy(types.RateLimitKeyPrefixLoginFail + audience + ":" + flow.Connection + ":" + principal).
		FailWindow(config.GetLoginACFailWindow(flow.Connection)).
		ThrottleAt(config.GetLoginACThreshold(flow.Connection))
}

// extractStringParam 安全地从 params 切片中提取 string 类型参数
func extractStringParam(params []any, index int) string {
	if index >= len(params) {
		return ""
	}
	if s, ok := params[index].(string); ok {
		return s
	}
	return ""
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
