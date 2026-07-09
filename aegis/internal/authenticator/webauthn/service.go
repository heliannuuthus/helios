// Package webauthn provides internal WebAuthn protocol engine for authentication flows.
package webauthn

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/internal/types"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/logger"
)

const (
	DefaultWebAuthnCeremonyTTL = 5 * time.Minute
)

// Service WebAuthn 协议引擎（internal，仅 aegis 内部使用）
type Service struct {
	webauthn    *webauthn.WebAuthn
	rpID        string
	cache       *cache.Manager
	credentials *hermes.Client
}

func NewService(cm *cache.Manager, credentials *hermes.Client) (*Service, error) {
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
		webauthn:    wa,
		rpID:        rpID,
		cache:       cm,
		credentials: credentials,
	}, nil
}

// GetRPID 获取 RP ID
func (s *Service) GetRPID() string {
	return s.rpID
}

// ==================== 注册流程 ====================

// InitializeRegistration 初始化注册，生成 WebAuthn creation options 并保存协议 session。
func (s *Service) InitializeRegistration(ctx context.Context, user *models.UserWithDecrypted, existingCredentials []*StoredWebAuthnCredential) (*RegistrationOptions, error) {
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
		logger.Errorf("[WebAuthn] InitializeRegistration failed: %v", err)
		return nil, fmt.Errorf("initialize registration failed: %w", err)
	}

	ceremonyID := types.GenerateChallengeID()
	if err := s.cache.SaveWebAuthnCeremony(ctx, &cache.WebAuthnCeremony{
		ID:          ceremonyID,
		Operation:   OperationRegistration,
		OpenID:      user.OpenID,
		SessionData: session,
	}, DefaultWebAuthnCeremonyTTL); err != nil {
		return nil, err
	}

	logger.Infof("[WebAuthn] InitializeRegistration success - OpenID: %s, CeremonyID: %s", user.OpenID, ceremonyID)

	return &RegistrationOptions{
		Options:    options,
		CeremonyID: ceremonyID,
	}, nil
}

// CompleteRegistration 完成注册，验证 attestation 并返回可保存的 WebAuthn credential。
func (s *Service) CompleteRegistration(ctx context.Context, ceremonyID string, r *http.Request) (*webauthn.Credential, error) {
	ceremony, err := s.cache.GetWebAuthnCeremony(ctx, ceremonyID)
	if err != nil {
		return nil, err
	}
	if ceremony.Operation != OperationRegistration {
		return nil, fmt.Errorf("invalid webauthn ceremony operation")
	}

	user, err := s.cache.GetUser(ctx, ceremony.OpenID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	existingCreds, err := s.getUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		logger.Warnf("[WebAuthn] get existing credentials failed: %v", err)
		existingCreds = nil
	}

	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
		credentials = append(credentials, cred.ToWebAuthnCredential())
	}

	webauthnUser := NewUser(user, credentials)

	credential, err := s.webauthn.FinishRegistration(webauthnUser, *ceremony.SessionData, r)
	if err != nil {
		logger.Errorf("[WebAuthn] CompleteRegistration failed: %v", err)
		return nil, fmt.Errorf("complete registration failed: %w", err)
	}

	if err := s.cache.DeleteWebAuthnCeremony(ctx, ceremonyID); err != nil {
		logger.Warnf("[WebAuthn] DeleteWebAuthnCeremony failed after registration: %v", err)
	}

	logger.Infof("[WebAuthn] CompleteRegistration success - OpenID: %s, CredentialID: %s",
		user.OpenID, base64.RawURLEncoding.EncodeToString(credential.ID))

	return credential, nil
}

// ==================== 登录流程 ====================

// InitializeAuthenticationCeremony creates assertion options and stores WebAuthn ceremony data.
func (s *Service) InitializeAuthenticationCeremony(ctx context.Context, ceremonyID string, user *models.UserWithDecrypted, existingCredentials []*StoredWebAuthnCredential, ttl time.Duration) (*protocol.CredentialAssertion, error) {
	if user == nil {
		return nil, fmt.Errorf("user is required")
	}

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
		logger.Errorf("[WebAuthn] InitializeAuthentication failed: %v", err)
		return nil, fmt.Errorf("initialize authentication failed: %w", err)
	}

	if ttl <= 0 {
		ttl = DefaultWebAuthnCeremonyTTL
	}
	if err := s.cache.SaveWebAuthnCeremony(ctx, &cache.WebAuthnCeremony{
		ID:          ceremonyID,
		Operation:   OperationLogin,
		OpenID:      user.OpenID,
		SessionData: session,
	}, ttl); err != nil {
		return nil, err
	}

	logger.Infof("[WebAuthn] InitializeAuthentication success - OpenID: %s, CeremonyID: %s", user.OpenID, ceremonyID)
	return options, nil
}

// InitializeDiscoverableAuthenticationCeremony creates discoverable login options and stores WebAuthn ceremony data.
func (s *Service) InitializeDiscoverableAuthenticationCeremony(ctx context.Context, ceremonyID string, ttl time.Duration) (*protocol.CredentialAssertion, error) {
	options, session, err := s.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		logger.Errorf("[WebAuthn] InitializeDiscoverableAuthentication failed: %v", err)
		return nil, fmt.Errorf("initialize discoverable authentication failed: %w", err)
	}

	if ttl <= 0 {
		ttl = DefaultWebAuthnCeremonyTTL
	}
	if err := s.cache.SaveWebAuthnCeremony(ctx, &cache.WebAuthnCeremony{
		ID:          ceremonyID,
		Operation:   OperationDiscoverableLogin,
		SessionData: session,
	}, ttl); err != nil {
		return nil, err
	}

	logger.Infof("[WebAuthn] InitializeDiscoverableAuthentication success - CeremonyID: %s", ceremonyID)
	return options, nil
}

// VerifyAuthentication 验证 assertion 并返回认证出的用户与凭证。
func (s *Service) VerifyAuthentication(ctx context.Context, ceremonyID string, assertionBody []byte) (string, *webauthn.Credential, error) {
	ceremony, err := s.cache.GetWebAuthnCeremony(ctx, ceremonyID)
	if err != nil {
		return "", nil, err
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(assertionBody)
	if err != nil {
		return "", nil, fmt.Errorf("parse credential assertion failed: %w", err)
	}

	var openid string
	var credential *webauthn.Credential

	if ceremony.Operation == OperationDiscoverableLogin {
		credential, err = s.verifyDiscoverableAuthentication(ctx, ceremony.SessionData, parsedResponse)
		if err != nil {
			return "", nil, err
		}
		openid, err = s.GetOpenIDByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
		if err != nil {
			return "", nil, fmt.Errorf("user not found for credential: %w", err)
		}
	} else {
		openid = ceremony.OpenID
		if openid == "" {
			return "", nil, fmt.Errorf("openid not found in session")
		}

		user, err := s.cache.GetUser(ctx, openid)
		if err != nil {
			return "", nil, fmt.Errorf("user not found: %w", err)
		}

		existingCreds, err := s.getUserWebAuthnCredentials(ctx, user.OpenID)
		if err != nil {
			return "", nil, fmt.Errorf("get credentials failed: %w", err)
		}

		credentials := make([]webauthn.Credential, 0, len(existingCreds))
		for _, cred := range existingCreds {
			credentials = append(credentials, cred.ToWebAuthnCredential())
		}

		webauthnUser := NewUser(user, credentials)

		credential, err = s.webauthn.ValidateLogin(webauthnUser, *ceremony.SessionData, parsedResponse)
		if err != nil {
			logger.Errorf("[WebAuthn] ValidateLogin failed: %v", err)
			return "", nil, fmt.Errorf("validate login failed: %w", err)
		}
	}

	if err := s.cache.DeleteWebAuthnCeremony(ctx, ceremonyID); err != nil {
		logger.Warnf("[WebAuthn] DeleteWebAuthnCeremony failed after login: %v", err)
	}

	logger.Infof("[WebAuthn] VerifyAuthentication success - OpenID: %s", openid)

	return openid, credential, nil
}

// ==================== 凭证管理 ====================

// SaveCredential 保存凭证
func (s *Service) SaveCredential(ctx context.Context, openid string, credential *webauthn.Credential) error {
	stored := FromWebAuthnCredential(credential)
	secretJSON, err := SerializeWebAuthnCredential(stored)
	if err != nil {
		return err
	}

	credentialID := EncodeCredentialID(stored.ID)
	dbCred := &models.UserCredential{
		OpenID:       openid,
		CredentialID: &credentialID,
		Type:         string(models.CredentialTypeWebAuthn),
		Label:        InferCredentialLabel(credential),
		Secret:       secretJSON,
		Enabled:      true,
	}

	return s.credentials.CreateCredential(ctx, dbCred)
}

// PatchCredentialSignCount 更新凭证签名计数
func (s *Service) PatchCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return s.credentials.PatchCredential(ctx, credentialID, map[string]any{
		"sign_count":   signCount,
		"last_used_at": time.Now(),
	})
}

// DeleteCredential 删除凭证
func (s *Service) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return s.credentials.DeleteCredential(ctx, openid, credentialID)
}

// ListCredentials 列出用户的所有 WebAuthn 凭证
func (s *Service) ListCredentials(ctx context.Context, openid string) ([]*StoredWebAuthnCredential, error) {
	return s.getUserWebAuthnCredentials(ctx, openid)
}

// GetOpenIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (s *Service) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	return s.credentials.GetOpenIDByCredentialID(ctx, credentialID)
}

// getUserWebAuthnCredentials 获取用户的 WebAuthn 凭证列表
func (s *Service) getUserWebAuthnCredentials(ctx context.Context, openid string) ([]*StoredWebAuthnCredential, error) {
	credentials, err := s.credentials.ListUserCredentialsByType(ctx, openid, string(models.CredentialTypeWebAuthn))
	if err != nil {
		return nil, err
	}

	result := make([]*StoredWebAuthnCredential, 0, len(credentials))
	for _, cred := range credentials {
		if !cred.Enabled {
			continue
		}
		stored, err := ParseStoredWebAuthnCredential(&cred)
		if err != nil {
			continue
		}
		result = append(result, stored)
	}

	return result, nil
}

// verifyDiscoverableAuthentication verifies a discoverable WebAuthn authentication assertion.
func (s *Service) verifyDiscoverableAuthentication(ctx context.Context, session *webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	credentialID := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)
	openid, err := s.GetOpenIDByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	user, err := s.cache.GetUser(ctx, openid)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	existingCreds, err := s.getUserWebAuthnCredentials(ctx, user.OpenID)
	if err != nil {
		return nil, fmt.Errorf("get credentials failed: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(existingCreds))
	for _, cred := range existingCreds {
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
