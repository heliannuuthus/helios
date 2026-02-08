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

	// 创建 Challenge 并保存会话数据
	challenge := types.NewChallenge(types.ChallengeTypeWebAuthn, DefaultWebAuthnSessionTTL)

	// 保存会话数据到 Challenge
	// session.Challenge 已经是 Base64URL 编码的字符串
	sessionData := &SessionData{
		UserID:      user.UID,
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData("session", string(sessionBytes))
	challenge.SetData("operation", "registration")

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge failed: %w", err)
	}

	logger.Infof("[WebAuthn] BeginRegistration success - UserID: %s, ChallengeID: %s", user.UID, challenge.ID)

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
	operation := challenge.GetStringData("operation")
	if operation != "registration" {
		return nil, fmt.Errorf("invalid challenge operation")
	}

	// 获取会话数据
	sessionStr := challenge.GetStringData("session")
	if sessionStr == "" {
		return nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	// 获取用户
	user, err := s.cache.GetUser(ctx, sessionData.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 获取用户已有凭证
	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.UID)
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

	logger.Infof("[WebAuthn] FinishRegistration success - UserID: %s, CredentialID: %s",
		user.UID, base64.RawURLEncoding.EncodeToString(credential.ID))

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

	// 创建 Challenge 并保存会话数据
	challenge := types.NewChallenge(types.ChallengeTypeWebAuthn, DefaultWebAuthnSessionTTL)

	// 保存会话数据
	sessionData := &SessionData{
		UserID:      user.UID,
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData("session", string(sessionBytes))
	challenge.SetData("operation", "login")

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge failed: %w", err)
	}

	logger.Infof("[WebAuthn] BeginLogin success - UserID: %s, ChallengeID: %s", user.UID, challenge.ID)

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

	// 创建 Challenge
	challenge := types.NewChallenge(types.ChallengeTypeWebAuthn, DefaultWebAuthnSessionTTL)

	// 保存会话数据
	sessionData := &SessionData{
		Challenge:   session.Challenge,
		SessionData: session,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session data failed: %w", err)
	}
	challenge.SetData("session", string(sessionBytes))
	challenge.SetData("operation", "discoverable_login")

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
func (s *Service) FinishLogin(ctx context.Context, challengeID string, r *http.Request) (string, *webauthn.Credential, error) {
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
	sessionStr := challenge.GetStringData("session")
	if sessionStr == "" {
		return "", nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return "", nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	// 检查操作类型
	operation := challenge.GetStringData("operation")

	var userID string
	var credential *webauthn.Credential

	if operation == "discoverable_login" {
		// Discoverable 登录：需要通过凭证 ID 查找用户
		credential, err = s.finishDiscoverableLogin(ctx, sessionData.SessionData, r)
		if err != nil {
			return "", nil, err
		}
		// 通过凭证 ID 查找用户
		userID, err = s.cache.GetUserIDByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			return "", nil, fmt.Errorf("user not found for credential: %w", err)
		}
	} else {
		// 普通登录
		userID = sessionData.UserID
		if userID == "" {
			return "", nil, fmt.Errorf("user id not found in session")
		}

		// 获取用户
		user, err := s.cache.GetUser(ctx, userID)
		if err != nil {
			return "", nil, fmt.Errorf("user not found: %w", err)
		}

		// 获取用户凭证
		existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.UID)
		if err != nil {
			return "", nil, fmt.Errorf("get credentials failed: %w", err)
		}

		credentials := make([]webauthn.Credential, 0, len(existingCredentials))
		for _, cred := range existingCredentials {
			credentials = append(credentials, cred.ToWebAuthnCredential())
		}

		// 创建 WebAuthn 用户
		webauthnUser := NewUser(user, credentials)

		// 完成登录验证
		credential, err = s.webauthn.FinishLogin(webauthnUser, *sessionData.SessionData, r)
		if err != nil {
			logger.Errorf("[WebAuthn] FinishLogin failed: %v", err)
			return "", nil, fmt.Errorf("finish login failed: %w", err)
		}
	}

	// 验证通过，删除临时 Challenge 会话
	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[WebAuthn] DeleteChallenge failed after login: %v", err)
	}

	logger.Infof("[WebAuthn] FinishLogin success - UserID: %s", userID)

	return userID, credential, nil
}

// finishDiscoverableLogin 完成可发现凭证登录
func (s *Service) finishDiscoverableLogin(ctx context.Context, session *webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	// 解析请求以获取凭证 ID
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, fmt.Errorf("parse credential request failed: %w", err)
	}

	// 通过凭证 ID 查找用户
	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	userID, err := s.cache.GetUserIDByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	// 获取用户
	user, err := s.cache.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// 获取用户凭证
	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.UID)
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
func (s *Service) SaveCredential(ctx context.Context, userID string, credential *webauthn.Credential) error {
	stored := cache.FromWebAuthnCredential(credential)
	return s.cache.SaveUserWebAuthnCredential(ctx, userID, stored)
}

// UpdateCredentialSignCount 更新凭证签名计数
func (s *Service) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return s.cache.UpdateWebAuthnCredentialSignCount(ctx, credentialID, signCount)
}

// DeleteCredential 删除凭证
func (s *Service) DeleteCredential(ctx context.Context, userID, credentialID string) error {
	return s.cache.DeleteUserWebAuthnCredential(ctx, userID, credentialID)
}

// ListCredentials 列出用户的所有 WebAuthn 凭证
func (s *Service) ListCredentials(ctx context.Context, userID string) ([]*cache.StoredWebAuthnCredential, error) {
	return s.cache.GetUserWebAuthnCredentials(ctx, userID)
}
