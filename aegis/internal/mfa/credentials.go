package mfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/logger"
)

// CredentialService owns MFA credential inventory operations.
type CredentialService struct {
	credentials *hermes.Client
}

func NewCredentialService(credentials *hermes.Client) *CredentialService {
	return &CredentialService{credentials: credentials}
}

func (s *CredentialService) Status(ctx context.Context, openid string) (*models.MFAStatus, error) {
	credentials, err := s.credentials.ListUserCredentials(ctx, openid)
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

func (s *CredentialService) List(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
	credentials, err := s.credentials.ListUserCredentials(ctx, openid)
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
			summary.CredentialID = *cred.CredentialID
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func (s *CredentialService) Update(ctx context.Context, openid, credType, credentialID string, updates map[string]any) error {
	if models.CredentialType(credType) == models.CredentialTypeTOTP {
		enabled, ok := updates["enabled"].(bool)
		if !ok {
			return errors.New("enabled is required for totp")
		}
		if enabled {
			return errors.New("启用 TOTP 请使用扫码绑定流程")
		}
		return s.Delete(ctx, openid, credType, "")
	}

	cred, err := s.credentials.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return errors.New("凭证不存在")
	}
	if cred.OpenID != openid {
		return errors.New("凭证不存在")
	}

	if enabled, ok := updates["enabled"].(bool); ok && !enabled {
		if err := s.credentials.DeleteCredential(ctx, openid, credentialID); err != nil {
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
	if err := s.credentials.PatchCredential(ctx, credentialID, patch); err != nil {
		return fmt.Errorf("更新凭证失败: %w", err)
	}
	return nil
}

func (s *CredentialService) Delete(ctx context.Context, openid, credType, credentialID string) error {
	if models.CredentialType(credType) == models.CredentialTypeTOTP {
		if err := s.credentials.DeleteUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP)); err != nil {
			return fmt.Errorf("删除 TOTP 凭证失败: %w", err)
		}
		logger.Infof("[Credential] TOTP 已禁用 - OpenID: %s", openid)
		return nil
	}

	if err := s.credentials.DeleteCredential(ctx, openid, credentialID); err != nil {
		return fmt.Errorf("删除凭证失败: %w", err)
	}
	logger.Infof("[Credential] MFA 凭证已删除 - OpenID: %s, Type: %s", openid, credType)
	return nil
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
