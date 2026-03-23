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

	"github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// CredentialStore 凭证 CRUD 存储接口
// hermes.UserService（直连）和 rpc/hermes.Client（gRPC）均可实现
type CredentialStore interface {
	CreateCredential(ctx context.Context, cred *models.UserCredential) error
	GetUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error)
	GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error)
	GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error)
	UpdateCredential(ctx context.Context, credentialID string, updates map[string]any) error
	UpdateCredentialByInternalID(ctx context.Context, id uint, updates map[string]any) error
	DeleteCredential(ctx context.Context, openid, credentialID string) error
	DeleteCredentialByOpenIDAndType(ctx context.Context, openid, credType string) error
}

// CredentialService 凭证业务服务（TOTP/WebAuthn 业务逻辑）
// 底层通过 CredentialStore 做 CRUD 存储
type CredentialService struct {
	store CredentialStore
}

// NewCredentialService 创建凭证业务服务
func NewCredentialService(store CredentialStore) *CredentialService {
	return &CredentialService{store: store}
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

func isPendingTOTPCredential(c *models.UserCredential) bool {
	return c.Type == string(models.CredentialTypeTOTP) && !isActiveTOTPCredential(c)
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

// SetupTOTP 初始化 TOTP（明文 Secret 交给 store，Hermes 层负责加密）
func (s *CredentialService) SetupTOTP(ctx context.Context, req *models.TOTPSetupRequest) (*models.TOTPSetupResponse, error) {
	creds, err := s.store.GetUserCredentialsByType(ctx, req.OpenID, string(models.CredentialTypeTOTP))
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
			return nil, fmt.Errorf("清理未完成的 TOTP 失败: %w", err)
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

	credential := &models.UserCredential{
		OpenID:  req.OpenID,
		Type:    string(models.CredentialTypeTOTP),
		Enabled: false,
		Secret:  secret,
	}

	if err := s.store.CreateCredential(ctx, credential); err != nil {
		return nil, fmt.Errorf("保存凭证失败: %w", err)
	}

	return &models.TOTPSetupResponse{
		Secret:       secret,
		OTPAuthURI:   otpauthURI,
		CredentialID: credential.ID,
	}, nil
}

// ConfirmTOTP 确认 TOTP 绑定（验证一次后写入 last_used_at）
func (s *CredentialService) ConfirmTOTP(ctx context.Context, req *models.ConfirmTOTPRequest) error {
	creds, err := s.store.GetUserCredentialsByType(ctx, req.OpenID, string(models.CredentialTypeTOTP))
	if err != nil {
		return fmt.Errorf("查询凭证失败: %w", err)
	}

	var credential *models.UserCredential
	for i := range creds {
		if creds[i].ID == req.CredentialID && isPendingTOTPCredential(&creds[i]) {
			credential = &creds[i]
			break
		}
	}
	if credential == nil {
		return errors.New("凭证不存在或已激活")
	}

	// Hermes 层已解密 TOTP Secret
	if !totp.Validate(req.Code, credential.Secret) {
		return errors.New("验证码错误")
	}

	now := time.Now()
	updates := map[string]any{
		"last_used_at": now,
		"enabled":      true,
	}
	if credential.CredentialID != nil {
		if err := s.store.UpdateCredential(ctx, *credential.CredentialID, updates); err != nil {
			return fmt.Errorf("确认 TOTP 失败: %w", err)
		}
	} else {
		if err := s.store.UpdateCredentialByInternalID(ctx, credential.ID, updates); err != nil {
			return fmt.Errorf("确认 TOTP 失败: %w", err)
		}
	}

	logger.Infof("[Credential] TOTP 绑定成功 - OpenID: %s", req.OpenID)
	return nil
}

// VerifyTOTP 验证 TOTP
func (s *CredentialService) VerifyTOTP(ctx context.Context, req *models.VerifyTOTPRequest) error {
	creds, err := s.store.GetUserCredentialsByType(ctx, req.OpenID, string(models.CredentialTypeTOTP))
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

// DisableTOTP 禁用 TOTP（按类型删除全部凭证行）
func (s *CredentialService) DisableTOTP(ctx context.Context, openid string) error {
	if err := s.store.DeleteCredentialByOpenIDAndType(ctx, openid, string(models.CredentialTypeTOTP)); err != nil {
		return fmt.Errorf("删除 TOTP 凭证失败: %w", err)
	}
	logger.Infof("[Credential] TOTP 已禁用 - OpenID: %s", openid)
	return nil
}

// SetTOTPEnabled 关闭 TOTP 即删除凭证；开启请走 Setup/Confirm 流程
func (s *CredentialService) SetTOTPEnabled(ctx context.Context, openid string, enabled bool) error {
	if enabled {
		return errors.New("启用 TOTP 请使用扫码绑定流程")
	}
	return s.DisableTOTP(ctx, openid)
}

// ==================== WebAuthn ====================

// SetWebAuthnEnabled 关闭即删除凭证；已存在则视为已启用
func (s *CredentialService) SetWebAuthnEnabled(ctx context.Context, openid, credentialID string, enabled bool) error {
	if enabled {
		cred, err := s.store.GetCredentialByID(ctx, credentialID)
		if err != nil {
			return errors.New("凭证不存在")
		}
		if cred.OpenID != openid {
			return errors.New("凭证不存在")
		}
		return nil
	}
	if err := s.store.DeleteCredential(ctx, openid, credentialID); err != nil {
		return fmt.Errorf("删除凭证失败: %w", err)
	}
	return nil
}

// DeleteWebAuthn 删除 WebAuthn 凭证
func (s *CredentialService) DeleteWebAuthn(ctx context.Context, openid, credentialID string) error {
	if err := s.store.DeleteCredential(ctx, openid, credentialID); err != nil {
		return fmt.Errorf("删除凭证失败: %w", err)
	}
	logger.Infof("[Credential] WebAuthn 已删除 - OpenID: %s", openid)
	return nil
}

// ==================== MFA 状态 ====================

// GetUserMFAStatus 获取用户 MFA 状态
func (s *CredentialService) GetUserMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error) {
	credentials, err := s.store.GetUserCredentials(ctx, openid)
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

// GetUserCredentialSummaries 获取用户凭证摘要列表
func (s *CredentialService) GetUserCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
	credentials, err := s.store.GetUserCredentials(ctx, openid)
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
