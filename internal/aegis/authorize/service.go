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

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/aegis/user"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
	"github.com/heliannuuthus/helios/pkg/helperutil"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 授权服务
type Service struct {
	cache    *cache.Manager
	userSvc  *user.Service
	tokenSvc *token.Service

	// 配置
	defaultAccessTTL  time.Duration
	defaultRefreshTTL time.Duration
	authCodeTTL       time.Duration
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache    *cache.Manager
	UserSvc  *user.Service
	TokenSvc *token.Service

	DefaultAccessTTL  time.Duration
	DefaultRefreshTTL time.Duration
	AuthCodeTTL       time.Duration
}

// NewService 创建授权服务
func NewService(cfg *ServiceConfig) *Service {
	return &Service{
		cache:             cfg.Cache,
		userSvc:           cfg.UserSvc,
		tokenSvc:          cfg.TokenSvc,
		defaultAccessTTL:  defaultDuration(cfg.DefaultAccessTTL, 2*time.Hour),
		defaultRefreshTTL: defaultDuration(cfg.DefaultRefreshTTL, 7*24*time.Hour),
		authCodeTTL:       defaultDuration(cfg.AuthCodeTTL, 5*time.Minute),
	}
}

func defaultDuration(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

// ==================== 授权准备 ====================

// PrepareAuthorization 准备授权
// 计算 scope 交集，检查身份要求，更新 AuthFlow.GrantedScopes
func (s *Service) PrepareAuthorization(ctx context.Context, flow *types.AuthFlow) error {
	if flow.User == nil {
		return autherrors.NewFlowInvalid("user not set in flow")
	}

	// 1. 检查服务的身份要求
	if err := s.checkIdentityRequirements(ctx, flow); err != nil {
		return err
	}

	// 2. 获取请求的 scope
	requestedScopes := flow.Request.ParseScopes()

	// 确保包含 openid
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

	// 3. 获取允许的 scope（由 aegis 统一控制，基于应用配置）
	// 验证 connection 存在
	connectionConfig := flow.ConnectionMap[flow.Connection]
	if connectionConfig == nil {
		return fmt.Errorf("connection %s not found in flow", flow.Connection)
	}

	// scope 由应用配置决定，不再从 connection 获取
	allowedScopes := s.getAllowedScopes(flow)
	if len(allowedScopes) == 0 {
		allowedScopes = []string{ScopeOpenID}
	}

	// 4. 计算交集
	grantedScopes := helperutil.ScopeIntersection(requestedScopes, allowedScopes)

	// 5. 检查是否有有效的 scope
	hasValidScope := false
	for _, scope := range grantedScopes {
		if scope != ScopeOpenID {
			hasValidScope = true
			break
		}
	}
	if !hasValidScope && len(grantedScopes) == 1 {
		// 只有 openid，没有其他 scope
		logger.Warnf("[Authorize] 没有有效的 scope - Requested: %v, Allowed: %v", requestedScopes, allowedScopes)
	}

	// 6. 更新 flow
	flow.SetAuthorized(grantedScopes)

	logger.Infof("[Authorize] 准备授权完成 - FlowID: %s, GrantedScopes: %v", flow.ID, grantedScopes)

	return nil
}

// checkIdentityRequirements 检查服务的身份要求
func (s *Service) checkIdentityRequirements(ctx context.Context, flow *types.AuthFlow) error {
	if flow.Service == nil {
		return nil
	}

	// 获取服务要求的身份类型
	requiredIdentities := flow.Service.GetRequiredIdentities()
	if len(requiredIdentities) == 0 {
		return nil // 不限制
	}

	// 获取用户已绑定的身份
	userIdentities, err := s.getUserIdentities(ctx, flow.User.UID)
	if err != nil {
		logger.Warnf("[Authorize] 获取用户身份失败: %v", err)
		return autherrors.NewServerError("failed to check identity requirements")
	}

	// 检查是否缺少必要的身份
	missingIdentities := s.getMissingIdentities(requiredIdentities, userIdentities)
	if len(missingIdentities) > 0 {
		logger.Infof("[Authorize] 用户 %s 缺少必要身份: %v", flow.User.UID, missingIdentities)
		return autherrors.NewIdentityRequired(missingIdentities)
	}

	return nil
}

// getUserIdentities 获取用户已绑定的身份类型列表
func (s *Service) getUserIdentities(ctx context.Context, uid string) ([]string, error) {
	return s.userSvc.GetIdentityTypes(ctx, uid)
}

// getMissingIdentities 获取缺少的身份类型
func (s *Service) getMissingIdentities(required, existing []string) []string {
	existingSet := make(map[string]bool)
	for _, id := range existing {
		existingSet[id] = true
	}

	var missing []string
	for _, req := range required {
		if !existingSet[req] {
			missing = append(missing, req)
		}
	}
	return missing
}

// GenerateAuthCode 生成授权码
func (s *Service) GenerateAuthCode(ctx context.Context, flow *types.AuthFlow) (*cache.AuthorizationCode, error) {
	now := time.Now()

	code := &cache.AuthorizationCode{
		Code:      types.GenerateAuthorizationCode(),
		FlowID:    flow.ID,
		State:     flow.Request.State,
		CreatedAt: now,
		ExpiresAt: now.Add(s.authCodeTTL),
		Used:      false,
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
	// 1. 获取授权码
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

	// 6. 标记授权码已使用
	if err := s.cache.MarkAuthCodeUsed(ctx, req.Code); err != nil {
		logger.Warnf("[Authorize] 标记授权码已使用失败: %v", err)
	}

	// 7. 生成 Token
	return s.generateTokens(ctx, &flow)
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
	user, err := s.userSvc.GetUser(ctx, rt.UserID)
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

	// 4. 生成新的 access token（使用 refresh token 中保存的 sub）
	tokenResp, err := s.generateAccessToken(ctx, app, svc, user, rt.Sub, rt.Scope)
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

	sub := getSub(flow.Identities, flow.Application.DomainID)
	if sub == "" {
		return nil, autherrors.NewServerError("failed to resolve user subject")
	}

	tokenResp, err := s.generateAccessToken(ctx, flow.Application, flow.Service, flow.User, sub, scope)
	if err != nil {
		return nil, err
	}

	// 如果 scope 包含 offline_access，生成 refresh token
	if helperutil.ContainsScope(flow.GrantedScopes, ScopeOfflineAccess) {
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
	// 计算 TTL
	accessTTL := time.Duration(svc.AccessTokenExpiresIn) * time.Second //nolint:gosec // AccessTokenExpiresIn 是配置的小整数，不会溢出
	if accessTTL == 0 {
		accessTTL = s.defaultAccessTTL
	}

	// 构建 UAT（用户信息根据 scope 自动过滤）
	// OpenID = sub（主身份 t_openid，对外暴露）
	// InternalUID = user.UID（内部关联 ID，不对外暴露，加密在 footer 中）
	uat := token.NewClaimsBuilder().
		Issuer(s.tokenSvc.GetIssuerName()).
		ClientID(app.AppID).
		Audience(svc.ServiceID).
		ExpiresIn(accessTTL).
		Build(token.NewUserAccessTokenBuilder().
			Scope(scope).
			OpenID(sub).
			InternalUID(user.UID).
			Nickname(user.GetNickname()).
			Picture(user.GetPicture()).
			Email(user.GetEmail()).
			Phone(user.GetPhone()))

	accessToken, err := s.tokenSvc.Issue(ctx, uat)
	if err != nil {
		return nil, fmt.Errorf("issue token failed: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		Scope:       scope,
	}, nil
}

func (s *Service) createRefreshToken(ctx context.Context, flow *types.AuthFlow, scope string) (*cache.RefreshToken, error) {
	// 计算 TTL
	refreshTTL := time.Duration(flow.Service.RefreshTokenExpiresIn) * time.Second //nolint:gosec // RefreshTokenExpiresIn 是配置的小整数，不会溢出
	if refreshTTL == 0 {
		refreshTTL = s.defaultRefreshTTL
	}

	// 清理旧的 refresh token
	s.cleanupOldRefreshTokens(ctx, flow.User.UID, flow.Application.AppID)

	// 生成 refresh token 值
	tokenValue, err := generateRefreshTokenValue()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 创建新的 refresh token
	now := time.Now()
	rt := &cache.RefreshToken{
		Token:     tokenValue,
		UserID:    flow.User.UID,
		Sub:       getSub(flow.Identities, flow.Application.DomainID),
		ClientID:  flow.Application.AppID,
		Audience:  flow.Service.ServiceID,
		Scope:     scope,
		ExpiresAt: now.Add(refreshTTL),
		CreatedAt: now,
	}

	if err := s.cache.SaveRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("save refresh token failed: %w", err)
	}

	return rt, nil
}

func (s *Service) cleanupOldRefreshTokens(ctx context.Context, userID, clientID string) {
	maxTokens := config.Aegis().GetInt("aegis.max-refresh-token")
	if maxTokens <= 0 {
		maxTokens = 10
	}

	tokens, err := s.cache.ListUserRefreshTokens(ctx, userID, clientID)
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

// ==================== 关系检查 ====================

// CheckRelation 检查用户是否具有指定的关系
func (s *Service) CheckRelation(ctx context.Context, serviceID, subjectID, relation, objectType, objectID string) (bool, error) {
	// 从 hermes 查询关系
	relationships, err := s.cache.ListRelationships(ctx, serviceID, "user", subjectID)
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

// ==================== Token 撤销 ====================

// RevokeToken 撤销 Token
func (s *Service) RevokeToken(ctx context.Context, tokenValue string) error {
	return s.cache.RevokeRefreshToken(ctx, tokenValue)
}

// RevokeAllTokens 撤销用户所有 Token
func (s *Service) RevokeAllTokens(ctx context.Context, userID string) error {
	return s.cache.RevokeUserRefreshTokens(ctx, userID)
}

// ==================== UserInfo ====================

// GetUserInfo 获取用户信息（根据 scope 脱敏）
// sub 是主身份的 t_openid（来自 token），用于对外返回
// internalOpenID 是内部 OpenID，用于查询用户信息
func (s *Service) GetUserInfo(ctx context.Context, sub, internalOpenID, scope string) (*UserInfoResponse, error) {
	user, err := s.userSvc.GetUser(ctx, internalOpenID)
	if err != nil {
		return nil, err
	}

	resp := &UserInfoResponse{
		Sub: sub,
	}

	scopes := parseScopeSet(scope)

	if scopes[ScopeProfile] {
		if user.Nickname != nil {
			resp.Nickname = *user.Nickname
		}
		if user.Picture != nil {
			resp.Picture = *user.Picture
		}
	}

	if scopes[ScopeEmail] && user.Email != nil {
		resp.Email = helperutil.MaskEmail(*user.Email)
	}

	if scopes[ScopePhone] && user.Phone != "" {
		resp.Phone = helperutil.MaskPhone(user.Phone)
	}

	return resp, nil
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

	// 3. 从域主密钥（32 字节 Ed25519 seed）直接解析公钥
	mainPublicKey, err := keys.ParsePublicKeyFromSeed(domain.Main)
	if err != nil {
		return nil, fmt.Errorf("parse main public key from seed: %w", err)
	}
	main := PublicKeyInfo{
		Version:   "v4",
		Purpose:   "public",
		PublicKey: keys.ExportPublicKeyBase64(mainPublicKey),
	}

	// 4. 从所有域密钥（32 字节 Ed25519 seed）直接解析公钥
	keyInfos := make([]PublicKeyInfo, 0, len(domain.Keys))
	for _, signKey := range domain.Keys {
		publicKey, err := keys.ParsePublicKeyFromSeed(signKey)
		if err != nil {
			return nil, fmt.Errorf("parse public key from seed: %w", err)
		}

		keyInfos = append(keyInfos, PublicKeyInfo{
			Version:   "v4",
			Purpose:   "public",
			PublicKey: keys.ExportPublicKeyBase64(publicKey),
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

// DecryptPhone 解密手机号
func DecryptPhone(cipher, openID string) (string, error) {
	key, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", err
	}
	return cryptoutil.Decrypt(key, cipher, openID)
}

// getSub 从身份列表中获取指定域的对外用户标识
func getSub(identities []*models.UserIdentity, domain string) string {
	for _, id := range identities {
		if id.Domain == domain && id.IDP == idp.TypeGlobal {
			return id.TOpenID
		}
	}
	return ""
}
