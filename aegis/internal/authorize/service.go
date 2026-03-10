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
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/async"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 授权服务
type Service struct {
	cache     *cache.Manager
	hermesSvc *hermes.Service
	userSvc   *user.Service
	tokenSvc  *token.Service
	pool      *async.Pool

	// 配置
	authCodeExpiresIn time.Duration
}

func defaultDuration(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
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

// NewService 创建授权服务
func NewService(
	cache *cache.Manager,
	hermesSvc *hermes.Service,
	userSvc *user.Service,
	tokenSvc *token.Service,
	pool *async.Pool,
	authCodeExpiresIn time.Duration,
) *Service {
	return &Service{
		cache:             cache,
		hermesSvc:         hermesSvc,
		userSvc:           userSvc,
		tokenSvc:          tokenSvc,
		pool:              pool,
		authCodeExpiresIn: defaultDuration(authCodeExpiresIn, 5*time.Minute),
	}
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
// openid scope 遵循 OIDC 规范：客户端请求时才授予，不强制注入
func (s *Service) ComputeGrantedScopes(flow *types.AuthFlow) ([]string, error) {
	connectionConfig := flow.ConnectionMap[flow.Connection]
	if connectionConfig == nil {
		return nil, fmt.Errorf("connection %s not found in flow", flow.Connection)
	}

	requestedScopes := helpers.ParseScopes(strings.Join(flow.Request.Scope, " "))

	allowedScopes := s.getAllowedScopes(flow)

	grantedScopes := helpers.ScopeIntersection(requestedScopes, allowedScopes)

	logger.Debugf("[Authorize] Scope 计算结果 - Requested: %q, Allowed: %q, Granted: %q", requestedScopes, allowedScopes, grantedScopes)

	if len(grantedScopes) == 0 {
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

	if err := s.cache.SetAuthCode(ctx, code); err != nil {
		return nil, fmt.Errorf("save auth code failed: %w", err)
	}

	// 更新 flow 状态
	flow.SetCompleted()

	logger.Infof("[Authorize] 生成授权码 - FlowID: %s, Code: %s...", flow.ID, code.Code[:8])

	return code, nil
}

// ==================== Token 交换 ====================

// ExchangeToken 单 audience 授权码换取 Token
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

// ==================== 多 Audience Token 交换 ====================

// ExchangeMultiAudienceToken 多 audience token 交换（仅 authorization_code）
// refresh_token 场景下每个 audience 独立刷新，走单 audience 的 ExchangeToken
func (s *Service) ExchangeMultiAudienceToken(ctx context.Context, req *MultiAudienceTokenRequest) (MultiAudienceTokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeMultiAudienceAuthorizationCode(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type for multi-audience: %s (use single-audience refresh_token instead)", req.GrantType)
	}
}

// ==================== 关系检查 ====================

// CheckRelation 检查用户是否具有指定的关系
func (s *Service) CheckRelations(ctx context.Context, serviceID, subjectID string, relations []string, objectType, objectID string) (map[string]bool, error) {
	relationships, err := s.hermesSvc.ListRelationships(ctx, serviceID, types.SubjectTypeUser, subjectID)
	if err != nil {
		return nil, err
	}

	results := make(map[string]bool, len(relations))
	for _, r := range relations {
		results[r] = false
	}

	for _, rel := range relationships {
		if objectType != "*" && rel.ObjectType != objectType && rel.ObjectType != "*" {
			continue
		}
		if objectID != "*" && rel.ObjectID != objectID && rel.ObjectID != "*" {
			continue
		}
		for _, r := range relations {
			if rel.Relation == r || rel.Relation == "*" {
				results[r] = true
			}
		}
	}

	return results, nil
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
func (s *Service) GetPublicKey(ctx context.Context, clientID string) (*PublicKeysResponse, error) {
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("domain not found: %w", err)
	}

	main := PublicKeyInfo{
		Version:   tokendef.PasetoVersion,
		Purpose:   tokendef.PasetoPurpose,
		PublicKey: base64.StdEncoding.EncodeToString(domain.Keys.Main.PublicKey),
	}

	keyInfos := make([]PublicKeyInfo, 0, len(domain.Keys.Keys))
	for _, k := range domain.Keys.Keys {
		keyInfos = append(keyInfos, PublicKeyInfo{
			Version:   tokendef.PasetoVersion,
			Purpose:   tokendef.PasetoPurpose,
			PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
		})
	}

	return &PublicKeysResponse{
		Main: main,
		Keys: keyInfos,
	}, nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	// 1. 原子消费授权码（读取并删除，防止重放）
	authCode, err := s.cache.GetAuthCode(ctx, req.Code)
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

	// 7. 异步清理 flow
	s.asyncCleanupFlow(ctx, authCode.FlowID)

	return resp, nil
}

func (s *Service) asyncCleanupFlow(ctx context.Context, flowID string) {
	s.pool.GoWithContext(ctx, func(ctx context.Context) {
		if err := s.cache.DeleteAuthFlow(ctx, flowID); err != nil {
			logger.Warnf("[Authorize] 清理 flow 失败 - FlowID: %s, Error: %v", flowID, err)
		}
	})
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
	tokenResp, err := s.generateAccessToken(ctx, &app.Application, &svc.Service, user, rt.OpenID, rt.Scope)
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

	// scope 包含 openid 时签发 id_token
	if helpers.ContainsScope(flow.GrantedScopes, ScopeOpenID) {
		logger.Infof("[Authorize] 签发 id_token - FlowID: %s, Sub: %s, GrantedScopes: %v", flow.ID, flow.User.OpenID, flow.GrantedScopes)
		idTokenStr, err := s.generateIDToken(ctx, flow)
		if err != nil {
			return nil, err
		}
		tokenResp.IDToken = idTokenStr
	} else {
		logger.Infof("[Authorize] 跳过 id_token 签发（scope 不含 openid） - FlowID: %s, GrantedScopes: %v", flow.ID, flow.GrantedScopes)
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
	app *models.Application,
	svc *models.Service,
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

// generateIDToken 签发 OIDC ID Token（v4.public，域密钥签名，不加密）
// aud = client_id（OIDC Core §2: id_token 的 audience 是 relying party 的 client_id）
func (s *Service) generateIDToken(ctx context.Context, flow *types.AuthFlow) (string, error) {
	scopes := parseScopeSet(strings.Join(flow.GrantedScopes, " "))

	idtBuilder := token.NewIDTokenBuilder()

	if scopes[ScopeProfile] {
		idtBuilder.Nickname(flow.User.GetNickname()).Picture(flow.User.GetPicture())
	}
	if flow.Request.Nonce != "" {
		idtBuilder.Nonce(flow.Request.Nonce)
	}

	idt := token.NewClaimsBuilder().
		Issuer(s.tokenSvc.GetIssuer()).
		Subject(flow.User.OpenID).
		Audience(flow.Application.AppID).
		ExpiresIn(time.Hour).
		Build(idtBuilder)

	return s.tokenSvc.Issue(ctx, idt)
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

	if err := s.cache.SetRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt, nil
}

func (s *Service) cleanupOldRefreshTokens(ctx context.Context, openid, clientID string) {
	maxTokens := config.Cfg().GetInt("aegis.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	tokens, err := s.cache.ListRefreshTokens(ctx, openid, clientID)
	if err != nil {
		return
	}

	if len(tokens) >= maxTokens {
		for i := maxTokens - 1; i < len(tokens); i++ {
			if err := s.cache.DelRefreshToken(ctx, tokens[i].Token); err != nil {
				// 记录错误但不中断流程
				logger.Warnf("revoke refresh token failed: %v", err)
			}
		}
	}
}

func (s *Service) exchangeMultiAudienceAuthorizationCode(ctx context.Context, req *MultiAudienceTokenRequest) (MultiAudienceTokenResponse, error) {
	// 1. 原子消费授权码
	authCode, err := s.cache.GetAuthCode(ctx, req.Code)
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

	// 4. 验证 redirect_uri（客户端不传时跳过，由授权阶段保证）
	if req.RedirectURI != "" && req.RedirectURI != flow.Request.RedirectURI {
		return nil, autherrors.NewInvalidGrant("redirect_uri mismatch")
	}

	// 5. 验证 PKCE
	if !verifyCodeChallenge(flow.Request.CodeChallengeMethod, flow.Request.CodeChallenge, req.CodeVerifier) {
		return nil, autherrors.NewInvalidGrant("invalid code verifier")
	}

	if flow.User == nil || flow.User.OpenID == "" {
		return nil, autherrors.NewServerError("failed to resolve user subject")
	}

	audiences, err := resolveAudiences(req.Audiences, flow.Request.Audiences)
	if err != nil {
		return nil, err
	}

	// 7. 为每个 audience 签发独立的 token
	resp, err := s.generateMultiAudienceTokens(ctx, &flow, audiences)
	if err != nil {
		return nil, err
	}

	// 8. scope 包含 openid 时签发 id_token（per-client，所有 audience 共享）
	if helpers.ContainsScope(flow.GrantedScopes, ScopeOpenID) {
		idTokenStr, err := s.generateIDToken(ctx, &flow)
		if err != nil {
			return nil, err
		}
		for _, tokenResp := range resp {
			tokenResp.IDToken = idTokenStr
		}
	}

	// 9. 异步清理 flow
	s.asyncCleanupFlow(ctx, authCode.FlowID)

	return resp, nil
}

// resolveAudiences 从 flow 或请求中解析 audiences（flow 优先）
func resolveAudiences(reqAudiences map[string]*AudienceScope, flowAudiences map[string]*types.RequestAudienceScope) (map[string]*AudienceScope, error) {
	audiences := reqAudiences
	if len(flowAudiences) > 0 {
		audiences = make(map[string]*AudienceScope, len(flowAudiences))
		for aud, ras := range flowAudiences {
			scope := ""
			if ras != nil {
				scope = ras.Scope
			}
			audiences[aud] = &AudienceScope{Scope: scope}
		}
	}
	if len(audiences) == 0 {
		return nil, autherrors.NewInvalidRequest("no audiences specified")
	}
	return audiences, nil
}

// generateMultiAudienceTokens 为多个 audience 生成独立的 token
func (s *Service) generateMultiAudienceTokens(
	ctx context.Context, flow *types.AuthFlow, audiences map[string]*AudienceScope,
) (MultiAudienceTokenResponse, error) {
	resp := make(MultiAudienceTokenResponse, len(audiences))

	relations, err := s.cache.GetAppServiceRelations(ctx, flow.Application.AppID)
	if err != nil {
		return nil, autherrors.NewServerError("check relation failed")
	}
	allowedSet := make(map[string]bool, len(relations))
	for _, rel := range relations {
		allowedSet[rel.ServiceID] = true
	}

	for audience, audienceScope := range audiences {
		if !allowedSet[audience] {
			return nil, autherrors.NewAccessDeniedf("application %s has no access to service %s", flow.Application.AppID, audience)
		}

		svc, err := s.cache.GetService(ctx, audience)
		if err != nil {
			return nil, autherrors.NewServiceNotFoundf("service not found: %s", audience)
		}

		scope := audienceScope.GetScope()

		// 签发 access token
		tokenResp, err := s.generateAccessToken(ctx, flow.Application, &svc.Service, flow.User, flow.User.OpenID, scope)
		if err != nil {
			return nil, fmt.Errorf("generate token for audience %s: %w", audience, err)
		}

		// 如果 scope 包含 offline_access，签发独立的 refresh token
		scopes := strings.Fields(scope)
		if helpers.ContainsScope(scopes, ScopeOfflineAccess) {
			rtValue, err := s.createRefreshTokenForAudience(ctx, flow.User.OpenID, flow.Application.AppID, &svc.Service, scope)
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
	ctx context.Context, openID, clientID string, svc *models.Service, scope string,
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

	if err := s.cache.SetRefreshToken(ctx, rt); err != nil {
		return "", fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt.Token, nil
}

// getAllowedScopes 获取允许的 scope
// scope 由 aegis 统一控制，默认允许所有标准 scope
func (s *Service) getAllowedScopes(_ *types.AuthFlow) []string {
	// TODO: 可以从应用配置或服务配置中读取
	// 目前默认允许所有标准 scope
	return []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, ScopeOfflineAccess}
}
