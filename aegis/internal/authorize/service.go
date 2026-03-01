package authorize

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/aegis/config"
	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/token"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/aegis/internal/user"
	"github.com/heliannuuthus/helios/hermes/models"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/async"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 授权服务
type Service struct {
	cache    *cache.Manager
	userSvc  *user.Service
	tokenSvc *token.Service
	pool     *async.Pool

	// 配置
	authCodeExpiresIn time.Duration
}

// NewService 创建授权服务
func NewService(
	cache *cache.Manager,
	userSvc *user.Service,
	tokenSvc *token.Service,
	pool *async.Pool,
	authCodeExpiresIn time.Duration,
) *Service {
	return &Service{
		cache:             cache,
		userSvc:           userSvc,
		tokenSvc:          tokenSvc,
		pool:              pool,
		authCodeExpiresIn: defaultDuration(authCodeExpiresIn, 5*time.Minute),
	}
}

func defaultDuration(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

// ==================== 授权准备 ====================

// CheckIdentityRequirements 检查服务的身份要求
// 返回 nil 表示满足要求或无限制
func (s *Service) CheckIdentityRequirements(ctx context.Context, flow *types.AuthFlow) error {
	if flow.User == nil {
		return autherrors.NewFlowInvalid("user not set in flow")
	}
	if flow.Service == nil {
		return nil
	}

	requiredIdentities := flow.Service.GetRequiredIdentities()
	if len(requiredIdentities) == 0 {
		return nil
	}

	userIdentities, err := s.userSvc.GetIdentityTypes(ctx, flow.User.OpenID)
	if err != nil {
		logger.Warnf("[Authorize] 获取用户身份失败: %v", err)
		return autherrors.NewServerError("failed to check identity requirements")
	}

	existingSet := make(map[string]bool, len(userIdentities))
	for _, id := range userIdentities {
		existingSet[id] = true
	}
	var missing []string
	for _, req := range requiredIdentities {
		if !existingSet[req] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		logger.Infof("[Authorize] 用户 %s 缺少必要身份: %v", flow.User.OpenID, missing)
		return autherrors.NewIdentityRequired(missing)
	}

	return nil
}

// ComputeGrantedScopes 计算授权的 scope 交集
// 返回最终授予的 scope 列表（至少包含 openid）
func (s *Service) ComputeGrantedScopes(flow *types.AuthFlow) ([]string, error) {
	connectionConfig := flow.ConnectionMap[flow.Connection]
	if connectionConfig == nil {
		return nil, fmt.Errorf("connection %s not found in flow", flow.Connection)
	}

	requestedScopes := helpers.ParseScopes(strings.Join(flow.Request.Scope, " "))
	hasOpenID := false
	for _, scope := range requestedScopes {
		if scope == ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		requestedScopes = append([]string{ScopeOpenID}, requestedScopes...)
	}

	allowedScopes := s.getAllowedScopes(flow)
	if len(allowedScopes) == 0 {
		allowedScopes = []string{ScopeOpenID}
	}

	grantedScopes := helpers.ScopeIntersection(requestedScopes, allowedScopes)

	logger.Debugf("[Authorize] Scope 计算结果 - Requested: %q, Allowed: %q, Granted: %q", requestedScopes, allowedScopes, grantedScopes)

	hasValidScope := false
	for _, scope := range grantedScopes {
		if scope != ScopeOpenID {
			hasValidScope = true
			break
		}
	}
	if !hasValidScope && len(grantedScopes) == 1 {
		logger.Warnf("[Authorize] 没有有效的 scope - Requested: %v, Allowed: %v", requestedScopes, allowedScopes)
	}

	return grantedScopes, nil
}

// GenerateAuthCode 生成授权码
func (s *Service) GenerateAuthCode(ctx context.Context, flow *types.AuthFlow) (*cache.AuthorizationCode, error) {
	now := time.Now()

	code := &cache.AuthorizationCode{
		Code:      types.GenerateAuthorizationCode(),
		FlowID:    flow.ID,
		State:     flow.Request.State,
		CreatedAt: now,
		ExpiresAt: now.Add(s.authCodeExpiresIn),
	}

	if err := s.cache.SaveAuthCode(ctx, code); err != nil {
		return nil, fmt.Errorf("save auth code failed: %w", err)
	}

	// 更新 flow 状态
	flow.SetCompleted()

	logger.Infof("[Authorize] 生成授权码 - FlowID: %s, Code: %s...", flow.ID, code.Code[:8])

	return code, nil
}

// ==================== Token 交换 ====================

// ExchangeToken 用授权码换取 Token
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.refreshToken(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 原子消费授权码（读取并删除，防止重放）
	authCode, err := s.cache.ConsumeAuthCode(ctx, req.Code)
	if err != nil {
		return nil, autherrors.NewInvalidGrant("invalid authorization code")
	}

	// 2. 获取 AuthFlow
	flowData, err := s.cache.GetAuthFlow(ctx, authCode.FlowID)
	if err != nil {
		return nil, autherrors.NewFlowNotFound("session not found")
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(flowData, &flow); err != nil {
		return nil, fmt.Errorf("unmarshal flow failed: %w", err)
	}

	// 3. 验证 client_id
	if req.ClientID != flow.Request.ClientID {
		return nil, autherrors.NewInvalidGrant("client_id mismatch")
	}

	// 4. 验证 redirect_uri
	if req.RedirectURI != flow.Request.RedirectURI {
		return nil, autherrors.NewInvalidGrant("redirect_uri mismatch")
	}

	// 5. 验证 PKCE
	if !verifyCodeChallenge(flow.Request.CodeChallengeMethod, flow.Request.CodeChallenge, req.CodeVerifier) {
		return nil, autherrors.NewInvalidGrant("invalid code verifier")
	}

	// 6. 生成 Token
	resp, err := s.generateTokens(ctx, &flow)
	if err != nil {
		return nil, err
	}

	// 7. Token 签发完成，flow 使命结束，异步清理
	flowID := authCode.FlowID
	s.pool.GoWithContext(ctx, func(ctx context.Context) {
		if err := s.cache.DeleteAuthFlow(ctx, flowID); err != nil {
			logger.Warnf("[Authorize] 清理 flow 失败 - FlowID: %s, Error: %v", flowID, err)
		}
	})

	return resp, nil
}

func (s *Service) refreshToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 获取 refresh token
	rt, err := s.cache.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, autherrors.NewInvalidGrant("invalid refresh token")
	}

	// 2. 验证 client_id
	if req.ClientID != rt.ClientID {
		return nil, autherrors.NewInvalidGrant("client_id mismatch")
	}

	// 3. 获取用户、应用、服务信息
	user, err := s.userSvc.GetUser(ctx, rt.OpenID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	app, err := s.cache.GetApplication(ctx, rt.ClientID)
	if err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	svc, err := s.cache.GetService(ctx, rt.Audience)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	// 4. 生成新的 access token（使用 refresh token 中保存的 openid 作为 sub）
	tokenResp, err := s.generateAccessToken(ctx, app, svc, user, rt.OpenID, rt.Scope)
	if err != nil {
		return nil, err
	}

	// 保持 refresh token 不变
	tokenResp.RefreshToken = rt.Token

	return tokenResp, nil
}

// generateTokens 生成 token（用于授权码交换）
func (s *Service) generateTokens(ctx context.Context, flow *types.AuthFlow) (*TokenResponse, error) {
	scope := strings.Join(flow.GrantedScopes, " ")

	if flow.User == nil || flow.User.OpenID == "" {
		return nil, autherrors.NewServerError("failed to resolve user subject")
	}

	// 签发 access token
	tokenResp, err := s.generateAccessToken(ctx, flow.Application, flow.Service, flow.User, flow.User.OpenID, scope)
	if err != nil {
		return nil, err
	}

	// 如果 scope 包含 offline_access，生成 refresh token
	if helpers.ContainsScope(flow.GrantedScopes, ScopeOfflineAccess) {
		rt, err := s.createRefreshToken(ctx, flow, scope)
		if err != nil {
			return nil, err
		}
		tokenResp.RefreshToken = rt.Token
	}

	return tokenResp, nil
}

func (s *Service) generateAccessToken(
	ctx context.Context,
	app *models.ApplicationWithKey,
	svc *models.ServiceWithKey,
	user *models.UserWithDecrypted,
	sub string,
	scope string,
) (*TokenResponse, error) {
	if svc.AccessTokenExpiresIn == 0 {
		return nil, autherrors.NewInvalidRequestf("access_token_expires_in not configured for service %s", svc.ServiceID)
	}
	accessExpiresIn := time.Duration(svc.AccessTokenExpiresIn) * time.Second //nolint:gosec // AccessTokenExpiresIn 是配置的小整数，不会溢出

	// 构建 UAT，用户信息根据 granted scope 过滤
	scopes := parseScopeSet(scope)
	uatBuilder := token.NewUserAccessTokenBuilder().
		Scope(scope).
		OpenID(sub)

	if scopes[ScopeProfile] {
		uatBuilder.Nickname(user.GetNickname()).Picture(user.GetPicture())
	}
	if scopes[ScopeEmail] {
		uatBuilder.Email(user.GetEmail())
	}
	if scopes[ScopePhone] {
		uatBuilder.Phone(user.GetPhone())
	}

	uat := token.NewClaimsBuilder().
		Issuer(s.tokenSvc.GetIssuer()).
		ClientID(app.AppID).
		Audience(svc.ServiceID).
		ExpiresIn(accessExpiresIn).
		Build(uatBuilder)

	accessToken, err := s.tokenSvc.Issue(ctx, uat)
	if err != nil {
		return nil, fmt.Errorf("issue token failed: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokendef.TokenTypeBearer,
		ExpiresIn:   int(accessExpiresIn.Seconds()),
		Scope:       scope,
	}, nil
}

func (s *Service) createRefreshToken(ctx context.Context, flow *types.AuthFlow, scope string) (*cache.RefreshToken, error) {
	if flow.Service.RefreshTokenExpiresIn == 0 {
		return nil, autherrors.NewInvalidRequestf("refresh_token_expires_in not configured for service %s", flow.Service.ServiceID)
	}
	refreshExpiresIn := time.Duration(flow.Service.RefreshTokenExpiresIn) * time.Second //nolint:gosec // RefreshTokenExpiresIn 是配置的小整数，不会溢出

	// 异步清理旧的 refresh token
	openid, clientID := flow.User.OpenID, flow.Application.AppID
	s.pool.GoWithContext(ctx, func(ctx context.Context) {
		s.cleanupOldRefreshTokens(ctx, openid, clientID)
	})

	// 生成 refresh token 值
	tokenValue, err := generateRefreshTokenValue()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 创建新的 refresh token
	now := time.Now()
	rt := &cache.RefreshToken{
		Token:     tokenValue,
		OpenID:    flow.User.OpenID,
		ClientID:  flow.Application.AppID,
		Audience:  flow.Service.ServiceID,
		Scope:     scope,
		ExpiresAt: now.Add(refreshExpiresIn),
		CreatedAt: now,
	}

	if err := s.cache.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt, nil
}

func (s *Service) cleanupOldRefreshTokens(ctx context.Context, openid, clientID string) {
	maxTokens := config.Cfg().GetInt("aegis.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	tokens, err := s.cache.ListUserRefreshTokens(ctx, openid, clientID)
	if err != nil {
		return
	}

	if len(tokens) >= maxTokens {
		for i := maxTokens - 1; i < len(tokens); i++ {
			if err := s.cache.RevokeRefreshToken(ctx, tokens[i].Token); err != nil {
				// 记录错误但不中断流程
				logger.Warnf("revoke refresh token failed: %v", err)
			}
		}
	}
}

// ==================== 多 Audience Token 交换 ====================

// ExchangeMultiAudienceToken 多 audience token 交换
func (s *Service) ExchangeMultiAudienceToken(ctx context.Context, req *MultiAudienceTokenRequest) (MultiAudienceTokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeMultiAudienceAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.refreshMultiAudienceToken(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}
}

func (s *Service) exchangeMultiAudienceAuthorizationCode(ctx context.Context, req *MultiAudienceTokenRequest) (MultiAudienceTokenResponse, error) {
	// 1. 原子消费授权码
	authCode, err := s.cache.ConsumeAuthCode(ctx, req.Code)
	if err != nil {
		return nil, autherrors.NewInvalidGrant("invalid authorization code")
	}

	// 2. 获取 AuthFlow
	flowData, err := s.cache.GetAuthFlow(ctx, authCode.FlowID)
	if err != nil {
		return nil, autherrors.NewFlowNotFound("session not found")
	}

	var flow types.AuthFlow
	if err := json.Unmarshal(flowData, &flow); err != nil {
		return nil, fmt.Errorf("unmarshal flow failed: %w", err)
	}

	// 3. 验证 client_id
	if req.ClientID != flow.Request.ClientID {
		return nil, autherrors.NewInvalidGrant("client_id mismatch")
	}

	// 4. 验证 redirect_uri
	if req.RedirectURI != flow.Request.RedirectURI {
		return nil, autherrors.NewInvalidGrant("redirect_uri mismatch")
	}

	// 5. 验证 PKCE
	if !verifyCodeChallenge(flow.Request.CodeChallengeMethod, flow.Request.CodeChallenge, req.CodeVerifier) {
		return nil, autherrors.NewInvalidGrant("invalid code verifier")
	}

	if flow.User == nil || flow.User.OpenID == "" {
		return nil, autherrors.NewServerError("failed to resolve user subject")
	}

	// 6. 为每个 audience 签发独立的 token
	resp, err := s.generateMultiAudienceTokens(ctx, &flow, req.Audiences)
	if err != nil {
		return nil, err
	}

	// 7. 异步清理 flow
	flowID := authCode.FlowID
	s.pool.GoWithContext(ctx, func(ctx context.Context) {
		if err := s.cache.DeleteAuthFlow(ctx, flowID); err != nil {
			logger.Warnf("[Authorize] 清理 flow 失败 - FlowID: %s, Error: %v", flowID, err)
		}
	})

	return resp, nil
}

func (s *Service) refreshMultiAudienceToken(ctx context.Context, req *MultiAudienceTokenRequest) (MultiAudienceTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, autherrors.NewInvalidRequest("refresh_token is required")
	}

	// 1. 获取 refresh token（用于验证 client_id 和获取用户信息）
	rt, err := s.cache.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, autherrors.NewInvalidGrant("invalid refresh token")
	}

	// 2. 验证 client_id
	if req.ClientID != rt.ClientID {
		return nil, autherrors.NewInvalidGrant("client_id mismatch")
	}

	// 3. 获取用户和应用信息
	user, err := s.userSvc.GetUser(ctx, rt.OpenID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	app, err := s.cache.GetApplication(ctx, rt.ClientID)
	if err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	// 4. 为每个 audience 签发独立的 token
	resp := make(MultiAudienceTokenResponse, len(req.Audiences))
	for audience, audienceScope := range req.Audiences {
		// 验证 Application-Service 关系
		hasRelation, err := s.cache.CheckAppServiceRelation(ctx, req.ClientID, audience)
		if err != nil {
			return nil, autherrors.NewServerError("check relation failed")
		}
		if !hasRelation {
			return nil, autherrors.NewAccessDeniedf("application %s has no access to service %s", req.ClientID, audience)
		}

		svc, err := s.cache.GetService(ctx, audience)
		if err != nil {
			return nil, autherrors.NewServiceNotFoundf("service not found: %s", audience)
		}

		scope := audienceScope.GetScope()

		// 签发 access token
		tokenResp, err := s.generateAccessToken(ctx, app, svc, user, rt.OpenID, scope)
		if err != nil {
			return nil, fmt.Errorf("generate token for audience %s: %w", audience, err)
		}

		// 如果 scope 包含 offline_access，签发独立的 refresh token
		scopes := strings.Fields(scope)
		if helpers.ContainsScope(scopes, ScopeOfflineAccess) {
			rtValue, err := s.createRefreshTokenForAudience(ctx, rt.OpenID, rt.ClientID, svc, scope)
			if err != nil {
				return nil, fmt.Errorf("create refresh token for audience %s: %w", audience, err)
			}
			tokenResp.RefreshToken = rtValue
		}

		resp[audience] = tokenResp
	}

	return resp, nil
}

// generateMultiAudienceTokens 为多个 audience 生成独立的 token
func (s *Service) generateMultiAudienceTokens(
	ctx context.Context, flow *types.AuthFlow, audiences map[string]*AudienceScope,
) (MultiAudienceTokenResponse, error) {
	resp := make(MultiAudienceTokenResponse, len(audiences))

	for audience, audienceScope := range audiences {
		// 验证 Application-Service 关系
		hasRelation, err := s.cache.CheckAppServiceRelation(ctx, flow.Application.AppID, audience)
		if err != nil {
			return nil, autherrors.NewServerError("check relation failed")
		}
		if !hasRelation {
			return nil, autherrors.NewAccessDeniedf("application %s has no access to service %s", flow.Application.AppID, audience)
		}

		svc, err := s.cache.GetService(ctx, audience)
		if err != nil {
			return nil, autherrors.NewServiceNotFoundf("service not found: %s", audience)
		}

		scope := audienceScope.GetScope()

		// 签发 access token
		tokenResp, err := s.generateAccessToken(ctx, flow.Application, svc, flow.User, flow.User.OpenID, scope)
		if err != nil {
			return nil, fmt.Errorf("generate token for audience %s: %w", audience, err)
		}

		// 如果 scope 包含 offline_access，签发独立的 refresh token
		scopes := strings.Fields(scope)
		if helpers.ContainsScope(scopes, ScopeOfflineAccess) {
			rtValue, err := s.createRefreshTokenForAudience(ctx, flow.User.OpenID, flow.Application.AppID, svc, scope)
			if err != nil {
				return nil, fmt.Errorf("create refresh token for audience %s: %w", audience, err)
			}
			tokenResp.RefreshToken = rtValue
		}

		resp[audience] = tokenResp
	}

	return resp, nil
}

// createRefreshTokenForAudience 为指定 audience 创建 refresh token
func (s *Service) createRefreshTokenForAudience(
	ctx context.Context, openID, clientID string, svc *models.ServiceWithKey, scope string,
) (string, error) {
	if svc.RefreshTokenExpiresIn == 0 {
		return "", autherrors.NewInvalidRequestf("refresh_token_expires_in not configured for service %s", svc.ServiceID)
	}
	refreshExpiresIn := time.Duration(svc.RefreshTokenExpiresIn) * time.Second //nolint:gosec // RefreshTokenExpiresIn 是配置的小整数，不会溢出

	// 异步清理旧的 refresh token
	s.pool.GoWithContext(ctx, func(ctx context.Context) {
		s.cleanupOldRefreshTokens(ctx, openID, clientID)
	})

	tokenValue, err := generateRefreshTokenValue()
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now()
	rt := &cache.RefreshToken{
		Token:     tokenValue,
		OpenID:    openID,
		ClientID:  clientID,
		Audience:  svc.ServiceID,
		Scope:     scope,
		ExpiresAt: now.Add(refreshExpiresIn),
		CreatedAt: now,
	}

	if err := s.cache.SaveRefreshToken(ctx, rt); err != nil {
		return "", fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt.Token, nil
}

// ==================== 关系检查 ====================

// CheckRelation 检查用户是否具有指定的关系
func (s *Service) CheckRelation(ctx context.Context, serviceID, subjectID, relation, objectType, objectID string) (bool, error) {
	// 从 hermes 查询关系
	relationships, err := s.cache.ListRelationships(ctx, serviceID, types.SubjectTypeUser, subjectID)
	if err != nil {
		return false, err
	}

	// 检查是否有匹配的关系
	for _, rel := range relationships {
		// 检查关系类型匹配
		if rel.Relation != relation && rel.Relation != "*" {
			continue
		}

		// 检查资源类型匹配
		if objectType != "*" && rel.ObjectType != objectType && rel.ObjectType != "*" {
			continue
		}

		// 检查资源 ID 匹配
		if objectID != "*" && rel.ObjectID != objectID && rel.ObjectID != "*" {
			continue
		}

		return true, nil
	}

	return false, nil
}

// ==================== Public Keys ====================

// PublicKeyInfo 公钥信息
type PublicKeyInfo struct {
	Version   string `json:"version"`    // PASETO 版本（v4）
	Purpose   string `json:"purpose"`    // 用途（public）
	PublicKey string `json:"public_key"` // Base64 编码的公钥
}

// PublicKeysResponse PASETO 公钥响应（支持密钥轮换）
type PublicKeysResponse struct {
	Main PublicKeyInfo   `json:"main"` // 当前主密钥（用于签发新 token）
	Keys []PublicKeyInfo `json:"keys"` // 所有有效公钥（包括主密钥和轮换中的旧密钥，用于验证）
}

// GetPublicKey 获取公钥（根据 client_id 返回其所属域的所有有效公钥）
// 返回的公钥列表包含主密钥和轮换期间的旧密钥，用于验证不同时期签发的 token
func (s *Service) GetPublicKey(ctx context.Context, clientID string) (*PublicKeysResponse, error) {
	// 1. 获取 Application
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	// 2. 获取域信息和公钥
	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}

	// 3. 从域主密钥（48 字节 seed）派生公钥
	mainSeed, err := pasetokit.ParseSeed(domain.Main)
	if err != nil {
		return nil, fmt.Errorf("parse main seed: %w", err)
	}
	mainPublicKey, err := mainSeed.DerivePublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive main public key: %w", err)
	}
	main := PublicKeyInfo{
		Version:   tokendef.PasetoVersion,
		Purpose:   tokendef.PasetoPurpose,
		PublicKey: pasetokit.ExportPublicKeyBase64(mainPublicKey),
	}

	// 4. 从所有域密钥（48 字节 seed）派生公钥
	keyInfos := make([]PublicKeyInfo, 0, len(domain.Keys))
	for _, signKey := range domain.Keys {
		seed, err := pasetokit.ParseSeed(signKey)
		if err != nil {
			return nil, fmt.Errorf("parse seed: %w", err)
		}
		publicKey, err := seed.DerivePublicKey()
		if err != nil {
			return nil, fmt.Errorf("derive public key: %w", err)
		}

		keyInfos = append(keyInfos, PublicKeyInfo{
			Version:   tokendef.PasetoVersion,
			Purpose:   tokendef.PasetoPurpose,
			PublicKey: pasetokit.ExportPublicKeyBase64(publicKey),
		})
	}

	// 5. 构建响应
	return &PublicKeysResponse{
		Main: main,
		Keys: keyInfos,
	}, nil
}

// ==================== 辅助函数 ====================

// verifyCodeChallenge 验证 PKCE
func verifyCodeChallenge(method, challenge, verifier string) bool {
	if verifier == "" {
		return false
	}

	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == challenge
	default:
		return false
	}
}

// parseScopeSet 解析 scope 为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}

// generateRefreshTokenValue 生成 refresh token 值
func generateRefreshTokenValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token value: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// getAllowedScopes 获取允许的 scope
// scope 由 aegis 统一控制，默认允许所有标准 scope
func (s *Service) getAllowedScopes(_ *types.AuthFlow) []string {
	// TODO: 可以从应用配置或服务配置中读取
	// 目前默认允许所有标准 scope
	return []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, ScopeOfflineAccess}
}
