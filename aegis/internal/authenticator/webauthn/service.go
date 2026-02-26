// Package webauthn provides internal WebAuthn protocol engine for authentication flows.
package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	DefaultWebAuthnSessionTTL = 5 * time.Minute
)

// Service WebAuthn 协议引擎（internal，仅 aegis 内部使用）
type Service struct {
	webauthn *webauthn.WebAuthn
	rpID     string
	cache    *cache.Manager
}

// NewService 创建 WebAuthn 服务
func NewService(cm *cache.Manager) (*Service, error) {
	cfg := config.Cfg()

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
func (s *Service) BeginRegistration(ctx context.Context, user *models.UserWithDecrypted, existingCredentials []*cache.StoredWebAuthnCredential) (*RegistrationBeginResponse, error) {
	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	webauthnUser := NewUser(user, credentials)
	exclusions := credentialsToExclusions(credentials)

	options, session, err := s.webauthn.BeginRegistration(
		webauthnUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.CrossPlatform,
			UserVerification:        protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginRegistration failed: %v", err)
		return nil, fmt.Errorf("begin registration failed: %w", err)
	}

	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL, nil, "")

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
func (s *Service) FinishRegistration(ctx context.Context, challengeID string, r *http.Request) (*webauthn.Credential, error) {
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found")
	}

	if challenge.IsExpired() {
		return nil, fmt.Errorf("challenge expired")
	}

	operation := challenge.GetStringData(types.ChallengeDataOperation)
	if operation != OperationRegistration {
		return nil, fmt.Errorf("invalid challenge operation")
	}

	sessionStr := challenge.GetStringData(types.ChallengeDataSession)
	if sessionStr == "" {
		return nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	user, err := s.cache.GetUser(ctx, sessionData.OpenID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		logger.Warnf("[WebAuthn] get existing credentials failed: %v", err)
		existingCredentials = nil
	}

	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	webauthnUser := NewUser(user, credentials)

	credential, err := s.webauthn.FinishRegistration(webauthnUser, *sessionData.SessionData, r)
	if err != nil {
		logger.Errorf("[WebAuthn] FinishRegistration failed: %v", err)
		return nil, fmt.Errorf("finish registration failed: %w", err)
	}

	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[WebAuthn] DeleteChallenge failed after registration: %v", err)
	}

	logger.Infof("[WebAuthn] FinishRegistration success - OpenID: %s, CredentialID: %s",
		user.OpenID, base64.RawURLEncoding.EncodeToString(credential.ID))

	return credential, nil
}

// ==================== 登录流程 ====================

// BeginLogin 开始登录
func (s *Service) BeginLogin(ctx context.Context, user *models.UserWithDecrypted, existingCredentials []*cache.StoredWebAuthnCredential) (*LoginBeginResponse, error) {
	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no webauthn credentials found for user")
	}

	webauthnUser := NewUser(user, credentials)
	allowedCredentials := credentialsToAllowed(credentials)

	options, session, err := s.webauthn.BeginLogin(
		webauthnUser,
		webauthn.WithAllowedCredentials(allowedCredentials),
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginLogin failed: %v", err)
		return nil, fmt.Errorf("begin login failed: %w", err)
	}

	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL, nil, "")

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
	options, session, err := s.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] BeginDiscoverableLogin failed: %v", err)
		return nil, fmt.Errorf("begin discoverable login failed: %w", err)
	}

	challenge := types.NewChallenge("", "", "", types.ChannelTypeWebAuthn, "", DefaultWebAuthnSessionTTL, nil, "")

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
func (s *Service) FinishLogin(ctx context.Context, challengeID string, assertionBody []byte) (string, *webauthn.Credential, error) {
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return "", nil, fmt.Errorf("challenge not found")
	}

	if challenge.IsExpired() {
		return "", nil, fmt.Errorf("challenge expired")
	}

	sessionStr := challenge.GetStringData(types.ChallengeDataSession)
	if sessionStr == "" {
		return "", nil, fmt.Errorf("session data not found")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		return "", nil, fmt.Errorf("unmarshal session data failed: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(assertionBody)
	if err != nil {
		return "", nil, fmt.Errorf("parse credential assertion failed: %w", err)
	}

	operation := challenge.GetStringData(types.ChallengeDataOperation)

	var openid string
	var credential *webauthn.Credential

	if operation == OperationDiscoverableLogin {
		credential, err = s.finishDiscoverableLogin(ctx, sessionData.SessionData, parsedResponse)
		if err != nil {
			return "", nil, err
		}
		openid, err = s.cache.GetOpenIDByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			return "", nil, fmt.Errorf("user not found for credential: %w", err)
		}
	} else {
		openid = sessionData.OpenID
		if openid == "" {
			return "", nil, fmt.Errorf("openid not found in session")
		}

		user, err := s.cache.GetUser(ctx, openid)
		if err != nil {
			return "", nil, fmt.Errorf("user not found: %w", err)
		}

		existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
		if err != nil {
			return "", nil, fmt.Errorf("get credentials failed: %w", err)
		}

		credentials := make([]webauthn.Credential, 0, len(existingCredentials))
		for _, cred := range existingCredentials {
			credentials = append(credentials, cred.ToWebAuthnCredential())
		}

		webauthnUser := NewUser(user, credentials)

		credential, err = s.webauthn.ValidateLogin(webauthnUser, *sessionData.SessionData, parsedResponse)
		if err != nil {
			logger.Errorf("[WebAuthn] ValidateLogin failed: %v", err)
			return "", nil, fmt.Errorf("validate login failed: %w", err)
		}
	}

	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[WebAuthn] DeleteChallenge failed after login: %v", err)
	}

	logger.Infof("[WebAuthn] FinishLogin success - OpenID: %s", openid)

	return openid, credential, nil
}

// finishDiscoverableLogin 完成可发现凭证登录
func (s *Service) finishDiscoverableLogin(ctx context.Context, session *webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	openid, err := s.cache.GetOpenIDByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	user, err := s.cache.GetUser(ctx, openid)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	existingCredentials, err := s.cache.GetUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		return nil, fmt.Errorf("get credentials failed: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(existingCredentials))
	for _, cred := range existingCredentials {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	webauthnUser := NewUser(user, credentials)

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

// SaveCredential 保存凭证
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
