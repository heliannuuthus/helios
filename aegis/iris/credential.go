package iris

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"

	aegisconfig "github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/contract"
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

// CredentialService 凭证业务服务（TOTP/WebAuthn 业务逻辑）
// 底层通过 CredentialStore 做 CRUD 存储
type CredentialService struct {
	store contract.CredentialStore
	cache *cache.Manager
}

// NewCredentialService 创建凭证业务服务
func NewCredentialService(store contract.CredentialStore, cacheManager *cache.Manager) (*CredentialService, error) {
	if store == nil {
		return nil, errors.New("credential store is required")
	}
	if cacheManager == nil {
		return nil, errors.New("credential cache is required")
	}
	return &CredentialService{store: store, cache: cacheManager}, nil
}

// ==================== TOTP ====================

// isActiveTOTPCredential TOTP 已绑定可用：已写 last_used_at，或兼容仅 enabled 的旧数据
func isActiveTOTPCredential(c *models.UserCredential) bool {
	if c.Type != string(models.CredentialTypeTOTP) {
		return false
	}
	if c.LastUsedAt != nil {
		return true
	}
	return c.Enabled
}

// credentialActiveInMFA MFA 展示与摘要：TOTP 按激活判定；WebAuthn 等以行存在且 enabled（遗留软禁用）
func credentialActiveInMFA(c *models.UserCredential) bool {
	switch models.CredentialType(c.Type) {
	case models.CredentialTypeTOTP:
		return isActiveTOTPCredential(c)
	default:
		return c.Enabled
	}
}

// BeginTOTP 初始化 TOTP pending MFA；确认成功后才写入凭证表
func (s *CredentialService) BeginTOTP(ctx context.Context, req *models.TOTPSetupRequest) (*models.TOTPSetupResponse, error) {
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
		if err := s.store.DeleteCredentialByOpenIDAndType(ctx, req.OpenID, string(models.CredentialTypeTOTP)); err != nil {
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

// CompleteTOTP 确认 TOTP 绑定（验证一次后写入凭证表）
func (s *CredentialService) CompleteTOTP(ctx context.Context, req *models.ConfirmTOTPRequest) error {
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

// VerifyTOTP 验证 TOTP
func (s *CredentialService) VerifyTOTP(ctx context.Context, req *models.VerifyTOTPRequest) error {
	creds, err := s.store.ListUserCredentialsByType(ctx, req.OpenID, string(models.CredentialTypeTOTP))
	if err != nil {
		return fmt.Errorf("查询凭证失败: %w", err)
	}
	var active []models.UserCredential
	for i := range creds {
		if isActiveTOTPCredential(&creds[i]) {
			active = append(active, creds[i])
		}
	}
	if len(active) == 0 {
		return errors.New("用户未绑定 TOTP")
	}

	if !totp.Validate(req.Code, active[0].Secret) {
		return errors.New("验证码错误")
	}

	return nil
}

// DeleteTOTP 禁用 TOTP（按类型删除全部凭证行）
func (s *CredentialService) DeleteTOTP(ctx context.Context, openid string) error {
	if err := s.store.DeleteCredentialByOpenIDAndType(ctx, openid, string(models.CredentialTypeTOTP)); err != nil {
		return fmt.Errorf("删除 TOTP 凭证失败: %w", err)
	}
	logger.Infof("[Credential] TOTP 已禁用 - OpenID: %s", openid)
	return nil
}

// PatchTOTP 关闭 TOTP 即删除凭证；开启请走 Setup/Confirm 流程
func (s *CredentialService) PatchTOTP(ctx context.Context, openid string, enabled bool) error {
	if enabled {
		return errors.New("启用 TOTP 请使用扫码绑定流程")
	}
	return s.DeleteTOTP(ctx, openid)
}

// ==================== WebAuthn ====================

// PatchWebAuthnCredential 更新 WebAuthn/Passkey 凭证元数据；关闭即删除凭证。
func (s *CredentialService) PatchWebAuthnCredential(ctx context.Context, openid, credentialID string, updates map[string]any) error {
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

// DeleteWebAuthnCredential 删除 WebAuthn 凭证
func (s *CredentialService) DeleteWebAuthnCredential(ctx context.Context, openid, credentialID string) error {
	if err := s.store.DeleteCredential(ctx, openid, credentialID); err != nil {
		return fmt.Errorf("删除凭证失败: %w", err)
	}
	logger.Infof("[Credential] WebAuthn 已删除 - OpenID: %s", openid)
	return nil
}

// ==================== MFA 状态 ====================

// GetMFAStatus 获取用户 MFA 状态
func (s *CredentialService) GetMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error) {
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

// ListCredentialSummaries 获取用户凭证摘要列表
func (s *CredentialService) ListCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
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
