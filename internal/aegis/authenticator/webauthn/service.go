// Package webauthn provides WebAuthn/Passkey authentication support.
package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	// 默认过期时间
	DefaultWebAuthnSessionTTL = 5 * time.Minute
)

// IsEnabled 检查 WebAuthn 是否启用
func IsEnabled() bool {
	return config.Aegis().GetBool("mfa.webauthn.enabled")
}

// Service WebAuthn 服务
type Service struct {
	webauthn *webauthn.WebAuthn
	rpID     string
	cache    *cache.Manager
}

// NewService 创建 WebAuthn 服务
func NewService(cm *cache.Manager) (*Service, error) {
	if !IsEnabled() {
		return nil, fmt.Errorf("webauthn is not enabled")
	}

	cfg := config.Aegis()

	rpID := cfg.GetString("mfa.webauthn.rp-id")
	if rpID == "" {
		rpID = "aegis.heliannuuthus.com"
	}

	rpDisplayName := cfg.GetString("mfa.webauthn.rp-display-name")
	if rpDisplayName == "" {
		rpDisplayName = "Helios Auth"
	}

	rpOrigins := cfg.GetStringSlice("mfa.webauthn.rp-origins")
	if len(rpOrigins) == 0 {
		rpOrigins = []string{"https://" + rpID}
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn failed: %w", err)
	}

	return &Service{
		webauthn: wa,
		rpID:     rpID,
		cache:    cm,
	}, nil
}

// GetRPID 获取 RP ID
func (s *Service) GetRPID() string {
	return s.rpID
}

// credentialsToExclusions 将凭证转换为排除列表
func credentialsToExclusions(credentials []webauthn.Credential) []protocol.CredentialDescriptor {
	exclusions := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, cred := range credentials {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		})
	}
	return exclusions
}

// credentialsToAllowed 将凭证转换为允许列表
func credentialsToAllowed(credentials []webauthn.Credential) []protocol.CredentialDescriptor {
	allowed := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, cred := range credentials {
		allowed = append(allowed, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		})
	}
	return allowed
}

// ==================== 注册流程 ====================

// BeginRegistration 开始注册
// 返回 WebAuthn 选项供前端使用
func (s *Service) BeginRegistration(ctx context.Context, user *models.UserWithDecrypted, existingCredentials []*cache.StoredWebAuthnCredential) (*RegistrationBeginResponse, error) {
	// 转换已有凭证为 webauthn.Credential
	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	// 创建 WebAuthn 用户
	webauthnUser := NewUser(user, credentials)

	// 转换为排除列表
	exclusions := credentialsToExclusions(credentials)

	// 生成注册选项
	options, session, err := s.webauthn.BeginRegistration(
		webauthnUser,
		webauthn.WithExclusions(exclusions), // 排除已有凭证
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred), // 支持 Passkey
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.CrossPlatform, // 支持跨平台认证器
			UserVerification:        protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginRegistration failed: %v", err)
		return nil, fmt.Errorf("begin registration failed: %w", err)
	}

	// 创建 Challenge 并保存会话数据（WebAuthn 内部会话，不携带 client/audience）
	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL)

	// 保存会话数据到 Challenge
	// session.Challenge 已经是 Base64URL 编码的字符串
	sessionData := &SessionData{
		OpenID:      user.OpenID,
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData(types.ChallengeDataSession, string(sessionBytes))
	challenge.SetData(types.ChallengeDataOperation, OperationRegistration)

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge failed: %w", err)
	}

	logger.Infof("[WebAuthn] BeginRegistration success - OpenID: %s, ChallengeID: %s", user.OpenID, challenge.ID)

	return &RegistrationBeginResponse{
		Options:     options,
		ChallengeID: challenge.ID,
	}, nil
}

// FinishRegistration 完成注册
// 验证前端返回的 attestation 并创建凭证
func (s *Service) FinishRegistration(ctx context.Context, challengeID string, r *http.Request) (*webauthn.Credential, error) {
	// 获取 Challenge
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found")
	}

	// 检查是否已过期
	if challenge.IsExpired() {
		return nil, fmt.Errorf("challenge expired")
	}

	// 检查操作类型
	operation := challenge.GetStringData(types.ChallengeDataOperation)
	if operation != OperationRegistration {
		return nil, fmt.Errorf("invalid challenge operation")
	}

	// 获取会话数据
	sessionStr := challenge.GetStringData(types.ChallengeDataSession)
	if sessionStr == "" {
		return nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	// 获取用户
	user, err := s.cache.GetUser(ctx, sessionData.OpenID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 获取用户已有凭证
	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		logger.Warnf("[WebAuthn] get existing credentials failed: %v", err)
		existingCredentials = nil
	}

	// 转换凭证
	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	// 创建 WebAuthn 用户
	webauthnUser := NewUser(user, credentials)

	// 完成注册验证
	credential, err := s.webauthn.FinishRegistration(webauthnUser, *sessionData.SessionData, r)
	if err != nil {
		logger.Errorf("[WebAuthn] FinishRegistration failed: %v", err)
		return nil, fmt.Errorf("finish registration failed: %w", err)
	}

	// 验证通过，删除临时 Challenge 会话
	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[WebAuthn] DeleteChallenge failed after registration: %v", err)
	}

	logger.Infof("[WebAuthn] FinishRegistration success - OpenID: %s, CredentialID: %s",
		user.OpenID, base64.RawURLEncoding.EncodeToString(credential.ID))

	return credential, nil
}

// ==================== 登录流程 ====================

// BeginLogin 开始登录
// 返回 WebAuthn 选项供前端使用
func (s *Service) BeginLogin(ctx context.Context, user *models.UserWithDecrypted, existingCredentials []*cache.StoredWebAuthnCredential) (*LoginBeginResponse, error) {
	// 转换已有凭证为 webauthn.Credential
	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no webauthn credentials found for user")
	}

	// 创建 WebAuthn 用户
	webauthnUser := NewUser(user, credentials)

	// 转换为允许列表
	allowedCredentials := credentialsToAllowed(credentials)

	// 生成登录选项
	options, session, err := s.webauthn.BeginLogin(
		webauthnUser,
		webauthn.WithAllowedCredentials(allowedCredentials),
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginLogin failed: %v", err)
		return nil, fmt.Errorf("begin login failed: %w", err)
	}

	// 创建 Challenge 并保存会话数据（WebAuthn 内部会话，不携带 client/audience）
	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL)

	// 保存会话数据
	sessionData := &SessionData{
		OpenID:      user.OpenID,
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData(types.ChallengeDataSession, string(sessionBytes))
	challenge.SetData(types.ChallengeDataOperation, OperationLogin)

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge failed: %w", err)
	}

	logger.Infof("[WebAuthn] BeginLogin success - OpenID: %s, ChallengeID: %s", user.OpenID, challenge.ID)

	return &LoginBeginResponse{
		Options:     options,
		ChallengeID: challenge.ID,
	}, nil
}

// BeginDiscoverableLogin 开始可发现凭证登录（Passkey 无用户名登录）
func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*LoginBeginResponse, error) {
	// 生成登录选项（不指定用户）
	options, session, err := s.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginDiscoverableLogin failed: %v", err)
		return nil, fmt.Errorf("begin discoverable login failed: %w", err)
	}

	// 创建 Challenge（WebAuthn 内部会话，不携带 client/audience）
	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL)

	// 保存会话数据
	sessionData := &SessionData{
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData(types.ChallengeDataSession, string(sessionBytes))
	challenge.SetData(types.ChallengeDataOperation, OperationDiscoverableLogin)

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge failed: %w", err)
	}

	logger.Infof("[WebAuthn] BeginDiscoverableLogin success - ChallengeID: %s", challenge.ID)

	return &LoginBeginResponse{
		Options:     options,
		ChallengeID: challenge.ID,
	}, nil
}

// FinishLogin 完成登录
// 验证前端返回的 assertion 并返回用户信息
// assertionBody: WebAuthn assertion JSON（前端 navigator.credentials.get() 的序列化结果）
func (s *Service) FinishLogin(ctx context.Context, challengeID string, assertionBody []byte) (string, *webauthn.Credential, error) {
	// 获取 Challenge
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return "", nil, fmt.Errorf("challenge not found")
	}

	// 检查是否已过期
	if challenge.IsExpired() {
		return "", nil, fmt.Errorf("challenge expired")
	}

	// 获取会话数据
	sessionStr := challenge.GetStringData(types.ChallengeDataSession)
	if sessionStr == "" {
		return "", nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return "", nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	// 解析 WebAuthn assertion
	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(assertionBody)
	if err != nil {
		return "", nil, fmt.Errorf("parse credential assertion failed: %w", err)
	}

	// 检查操作类型
	operation := challenge.GetStringData(types.ChallengeDataOperation)

	var openid string
	var credential *webauthn.Credential

	if operation == OperationDiscoverableLogin {
		// Discoverable 登录：需要通过凭证 ID 查找用户
		credential, err = s.finishDiscoverableLogin(ctx, sessionData.SessionData, parsedResponse)
		if err != nil {
			return "", nil, err
		}
		// 通过凭证 ID 查找用户
		openid, err = s.cache.GetOpenIDByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			return "", nil, fmt.Errorf("user not found for credential: %w", err)
		}
	} else {
		// 普通登录
		openid = sessionData.OpenID
		if openid == "" {
			return "", nil, fmt.Errorf("openid not found in session")
		}

		// 获取用户
		user, err := s.cache.GetUser(ctx, openid)
		if err != nil {
			return "", nil, fmt.Errorf("user not found: %w", err)
		}

		// 获取用户凭证
		existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
		if err != nil {
			return "", nil, fmt.Errorf("get credentials failed: %w", err)
		}

		credentials := make([]webauthn.Credential, 0, len(existingCredentials))
		for _, cred := range existingCredentials {
			credentials = append(credentials, cred.ToWebAuthnCredential())
		}

		// 创建 WebAuthn 用户
		webauthnUser := NewUser(user, credentials)

		// 完成登录验证（使用 ValidateLogin 替代 FinishLogin，不依赖 *http.Request）
		credential, err = s.webauthn.ValidateLogin(webauthnUser, *sessionData.SessionData, parsedResponse)
		if err != nil {
			logger.Errorf("[WebAuthn] ValidateLogin failed: %v", err)
			return "", nil, fmt.Errorf("validate login failed: %w", err)
		}
	}

	// 验证通过，删除临时 Challenge 会话
	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[WebAuthn] DeleteChallenge failed after login: %v", err)
	}

	logger.Infof("[WebAuthn] FinishLogin success - OpenID: %s", openid)

	return openid, credential, nil
}

// finishDiscoverableLogin 完成可发现凭证登录
func (s *Service) finishDiscoverableLogin(ctx context.Context, session *webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	// 通过凭证 ID 查找用户
	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	openid, err := s.cache.GetOpenIDByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	// 获取用户
	user, err := s.cache.GetUser(ctx, openid)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 获取用户凭证
	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		return nil, fmt.Errorf("get credentials failed: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	// 创建 WebAuthn 用户
	webauthnUser := NewUser(user, credentials)

	// 完成验证
	credential, err := s.webauthn.ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			return webauthnUser, nil
		},
		*session,
		parsedResponse,
	)
	if err != nil {
		return nil, fmt.Errorf("validate discoverable login failed: %w", err)
	}

	return credential, nil
}

// ==================== 凭证管理 ====================

// SaveCredential 保存凭证到数据库
func (s *Service) SaveCredential(ctx context.Context, openid string, credential *webauthn.Credential) error {
	stored := cache.FromWebAuthnCredential(credential)
	return s.cache.SaveUserWebAuthnCredential(ctx, openid, stored)
}

// UpdateCredentialSignCount 更新凭证签名计数
func (s *Service) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return s.cache.UpdateWebAuthnCredentialSignCount(ctx, credentialID, signCount)
}

// DeleteCredential 删除凭证
func (s *Service) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return s.cache.DeleteUserWebAuthnCredential(ctx, openid, credentialID)
}

// ListCredentials 列出用户的所有 WebAuthn 凭证
func (s *Service) ListCredentials(ctx context.Context, openid string) ([]*cache.StoredWebAuthnCredential, error) {
	return s.cache.GetUserWebAuthnCredentials(ctx, openid)
}
