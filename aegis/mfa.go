package aegis

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"

	aegisconfig "github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/contract"
	"github.com/heliannuuthus/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/internal/types"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/pkg/logger"
)

const (
	pendingMFATypeTOTP = "mfa:totp"

	pendingMFADataOpenID = "openid"
	pendingMFADataSecret = "secret"
	pendingMFADataLabel  = "label"
)

// MFAService owns MFA orchestration. Handlers talk to this service; WebAuthn
// remains the protocol engine behind passkey/webauthn flows.
type MFAService struct {
	store       contract.CredentialStore
	cache       *cache.Manager
	webauthnSvc *webauthn.Service
}

// NewMFAService 创建 MFA 服务
func NewMFAService(store contract.CredentialStore, cacheManager *cache.Manager, webauthnSvc *webauthn.Service) *MFAService {
	return &MFAService{
		store:       store,
		cache:       cacheManager,
		webauthnSvc: webauthnSvc,
	}
}

// GetRPID 获取 WebAuthn RP ID
func (s *MFAService) GetRPID() string {
	return s.webauthnSvc.GetRPID()
}

func isActiveTOTPCredential(c *models.UserCredential) bool {
	if c.Type != string(models.CredentialTypeTOTP) {
		return false
	}
	if c.LastUsedAt != nil {
		return true
	}
	return c.Enabled
}

func credentialActiveInMFA(c *models.UserCredential) bool {
	switch models.CredentialType(c.Type) {
	case models.CredentialTypeTOTP:
		return isActiveTOTPCredential(c)
	default:
		return c.Enabled
	}
}

func (s *MFAService) CreateTOTPEnrollment(ctx context.Context, req *models.TOTPSetupRequest) (*models.TOTPSetupResponse, error) {
	creds, err := s.store.ListUserCredentialsByType(ctx, req.OpenID, string(models.CredentialTypeTOTP))
	if err != nil {
		return nil, fmt.Errorf("查询 TOTP 失败: %w", err)
	}
	for i := range creds {
		if isActiveTOTPCredential(&creds[i]) {
			return nil, errors.New("用户已绑定 TOTP")
		}
	}
	if len(creds) > 0 {
		if err := s.deleteCredentials(ctx, req.OpenID, creds); err != nil {
			return nil, fmt.Errorf("清理历史未激活 TOTP 失败: %w", err)
		}
	}

	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	issuer := req.AppName
	if issuer == "" {
		issuer = "Helios"
	}

	otpauthURI := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(req.OpenID), secret, url.QueryEscape(issuer))

	challenge := types.NewChallenge(
		"",
		"",
		pendingMFATypeTOTP,
		types.ChannelTypeTOTP,
		req.OpenID,
		aegisconfig.GetChallengeBusinessExpiresIn(),
		nil,
		"",
	)
	challenge.SetData(pendingMFADataOpenID, req.OpenID)
	challenge.SetData(pendingMFADataSecret, secret)
	challenge.SetData(pendingMFADataLabel, "身份验证器 App")
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("保存 TOTP pending MFA 失败: %w", err)
	}

	return &models.TOTPSetupResponse{
		UID:        challenge.ID,
		Secret:     secret,
		OTPAuthURI: otpauthURI,
	}, nil
}

func (s *MFAService) ConfirmTOTPEnrollment(ctx context.Context, req *models.ConfirmTOTPRequest) error {
	challenge, err := s.cache.GetChallenge(ctx, req.UID)
	if err != nil {
		return errors.New("pending MFA 不存在或已过期")
	}
	if challenge.IsExpired() {
		return errors.New("pending MFA 已过期")
	}
	if challenge.Type != pendingMFATypeTOTP || challenge.ChannelType != types.ChannelTypeTOTP {
		return errors.New("pending MFA 类型不匹配")
	}
	if challenge.GetStringData(pendingMFADataOpenID) != req.OpenID {
		return errors.New("pending MFA 不存在")
	}

	secret := challenge.GetStringData(pendingMFADataSecret)
	if secret == "" {
		return errors.New("pending MFA 数据无效")
	}
	if !totp.Validate(req.Code, secret) {
		return errors.New("验证码错误")
	}

	now := time.Now()
	credential := &models.UserCredential{
		OpenID:     req.OpenID,
		Type:       string(models.CredentialTypeTOTP),
		Label:      challenge.GetStringData(pendingMFADataLabel),
		Enabled:    true,
		LastUsedAt: &now,
		Secret:     secret,
	}
	if credential.Label == "" {
		credential.Label = "身份验证器 App"
	}
	if err := s.store.CreateCredential(ctx, credential); err != nil {
		return fmt.Errorf("保存 TOTP 凭证失败: %w", err)
	}
	if err := s.cache.DeleteChallenge(ctx, req.UID); err != nil {
		logger.Warnf("[Credential] 删除 TOTP pending MFA 失败 - UID: %s, err: %v", req.UID, err)
	}

	logger.Infof("[Credential] TOTP 绑定成功 - OpenID: %s", req.OpenID)
	return nil
}

func (s *MFAService) UpdateCredential(ctx context.Context, openid, credType, credentialID string, updates map[string]any) error {
	if models.CredentialType(credType) == models.CredentialTypeTOTP {
		enabled, ok := updates["enabled"].(bool)
		if !ok {
			return errors.New("enabled is required for totp")
		}
		if enabled {
			return errors.New("启用 TOTP 请使用扫码绑定流程")
		}
		return s.DeleteCredential(ctx, openid, credType, "")
	}

	cred, err := s.store.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return errors.New("凭证不存在")
	}
	if cred.OpenID != openid {
		return errors.New("凭证不存在")
	}

	if enabled, ok := updates["enabled"].(bool); ok && !enabled {
		if err := s.store.DeleteCredential(ctx, openid, credentialID); err != nil {
			return fmt.Errorf("删除凭证失败: %w", err)
		}
		return nil
	}

	patch := make(map[string]any)
	if label, ok := updates["label"].(string); ok {
		if label == "" {
			return errors.New("label is required")
		}
		patch["label"] = label
	}
	if enabled, ok := updates["enabled"].(bool); ok {
		patch["enabled"] = enabled
	}
	if len(patch) == 0 {
		return nil
	}
	if err := s.store.PatchCredential(ctx, credentialID, patch); err != nil {
		return fmt.Errorf("更新凭证失败: %w", err)
	}
	return nil
}

func (s *MFAService) DeleteCredential(ctx context.Context, openid, credType, credentialID string) error {
	if models.CredentialType(credType) == models.CredentialTypeTOTP {
		credentials, err := s.store.ListUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP))
		if err != nil {
			return fmt.Errorf("查询 TOTP 凭证失败: %w", err)
		}
		if err := s.deleteCredentials(ctx, openid, credentials); err != nil {
			return fmt.Errorf("删除 TOTP 凭证失败: %w", err)
		}
		logger.Infof("[Credential] TOTP 已禁用 - OpenID: %s", openid)
		return nil
	}

	if err := s.store.DeleteCredential(ctx, openid, credentialID); err != nil {
		return fmt.Errorf("删除凭证失败: %w", err)
	}
	logger.Infof("[Credential] MFA 凭证已删除 - OpenID: %s, Type: %s", openid, credType)
	return nil
}

func (s *MFAService) Status(ctx context.Context, openid string) (*models.MFAStatus, error) {
	credentials, err := s.store.ListUserCredentials(ctx, openid)
	if err != nil {
		return nil, err
	}

	status := &models.MFAStatus{}
	for _, cred := range credentials {
		if !credentialActiveInMFA(&cred) {
			continue
		}
		switch models.CredentialType(cred.Type) {
		case models.CredentialTypeTOTP:
			status.TOTPEnabled = true
		case models.CredentialTypeWebAuthn:
			status.WebAuthnCount++
		case models.CredentialTypePasskey:
			status.PasskeyCount++
		}
	}
	return status, nil
}

func (s *MFAService) ListCredentials(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
	credentials, err := s.store.ListUserCredentials(ctx, openid)
	if err != nil {
		return nil, err
	}

	summaries := make([]models.CredentialSummary, 0, len(credentials))
	for _, cred := range credentials {
		if !credentialActiveInMFA(&cred) {
			continue
		}
		summary := models.CredentialSummary{
			ID:         cred.ID,
			Type:       cred.Type,
			Label:      cred.Label,
			Enabled:    credentialActiveInMFA(&cred),
			LastUsedAt: cred.LastUsedAt,
			CreatedAt:  cred.CreatedAt,
		}
		if cred.CredentialID != nil {
			credID := *cred.CredentialID
			if len(credID) > 16 {
				summary.CredentialID = credID[:16] + "..."
			} else {
				summary.CredentialID = credID
			}
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

// ==================== 对外类型定义 ====================

// WebAuthnBeginResponse WebAuthn 流程开始响应（注册或验证）
type WebAuthnBeginResponse struct {
	ChallengeID string `json:"challenge_id"`
	Options     any    `json:"options"`
}

// WebAuthnCredentialInfo 凭证信息
type WebAuthnCredentialInfo struct {
	ID        []byte `json:"id"`
	SignCount uint32 `json:"sign_count"`
}

// ==================== WebAuthn 凭证注册 ====================

// CreateWebAuthnEnrollment 开始 WebAuthn 凭证绑定。
func (s *MFAService) CreateWebAuthnEnrollment(ctx context.Context, user *models.UserWithDecrypted) (*WebAuthnBeginResponse, error) {
	existingCredentials, err := s.webauthnSvc.ListCredentials(ctx, user.OpenID)
	if err != nil {
		existingCredentials = nil
	}

	resp, err := s.webauthnSvc.InitializeRegistration(ctx, user, existingCredentials)
	if err != nil {
		return nil, err
	}

	return &WebAuthnBeginResponse{
		ChallengeID: resp.CeremonyID,
		Options:     resp.Options,
	}, nil
}

// ConfirmWebAuthnEnrollment 完成 WebAuthn 凭证绑定并保存凭证。
func (s *MFAService) ConfirmWebAuthnEnrollment(ctx context.Context, openid, challengeID string, r *http.Request) (*WebAuthnCredentialInfo, error) {
	credential, err := s.webauthnSvc.CompleteRegistration(ctx, challengeID, r)
	if err != nil {
		return nil, err
	}

	if err := s.webauthnSvc.SaveCredential(ctx, openid, credential); err != nil {
		return nil, err
	}

	return &WebAuthnCredentialInfo{
		ID:        credential.ID,
		SignCount: credential.Authenticator.SignCount,
	}, nil
}

// ==================== WebAuthn 凭证查询 ====================

// HasWebAuthnCredentials 检查用户是否有 WebAuthn 凭证
func (s *MFAService) HasWebAuthnCredentials(ctx context.Context, openid string) (bool, error) {
	creds, err := s.webauthnSvc.ListCredentials(ctx, openid)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

func (s *MFAService) deleteCredentials(ctx context.Context, openid string, credentials []models.UserCredential) error {
	for i := range credentials {
		credentialID := credentials[i].CredentialID
		if credentialID == nil || *credentialID == "" {
			continue
		}
		if err := s.store.DeleteCredential(ctx, openid, *credentialID); err != nil {
			return err
		}
	}
	return nil
}
