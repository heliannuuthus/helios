package aegis

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/heliannuuthus/helios/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// MFAService 对外暴露的 MFA 服务门面
// 封装 WebAuthn 凭证管理和验证操作，供 iris 等外部模块使用
type MFAService struct {
	webauthnSvc *webauthn.Service
}

// NewMFAService 创建 MFA 服务
func NewMFAService(webauthnSvc *webauthn.Service) *MFAService {
	return &MFAService{
		webauthnSvc: webauthnSvc,
	}
}

// WebAuthnEnabled 检查 WebAuthn 是否可用
func (s *MFAService) WebAuthnEnabled() bool {
	return s.webauthnSvc != nil
}

// GetRPID 获取 WebAuthn RP ID
func (s *MFAService) GetRPID() string {
	if s.webauthnSvc == nil {
		return ""
	}
	return s.webauthnSvc.GetRPID()
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

// BeginWebAuthnRegistration 开始 WebAuthn 凭证注册
func (s *MFAService) BeginWebAuthnRegistration(ctx context.Context, user *models.UserWithDecrypted) (*WebAuthnBeginResponse, error) {
	existingCredentials, err := s.webauthnSvc.ListCredentials(ctx, user.OpenID)
	if err != nil {
		existingCredentials = nil
	}

	resp, err := s.webauthnSvc.BeginRegistration(ctx, user, existingCredentials)
	if err != nil {
		return nil, err
	}

	return &WebAuthnBeginResponse{
		ChallengeID: resp.ChallengeID,
		Options:     resp.Options,
	}, nil
}

// FinishWebAuthnRegistration 完成 WebAuthn 凭证注册并保存凭证
func (s *MFAService) FinishWebAuthnRegistration(ctx context.Context, openid, challengeID string, r *http.Request) (*WebAuthnCredentialInfo, error) {
	credential, err := s.webauthnSvc.FinishRegistration(ctx, challengeID, r)
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

// ==================== WebAuthn 凭证验证 ====================

// BeginWebAuthnVerification 开始 WebAuthn 凭证验证（MFA 验证场景）
func (s *MFAService) BeginWebAuthnVerification(ctx context.Context, user *models.UserWithDecrypted) (*WebAuthnBeginResponse, error) {
	existingCredentials, err := s.webauthnSvc.ListCredentials(ctx, user.OpenID)
	if err != nil {
		return nil, err
	}

	if len(existingCredentials) == 0 {
		return nil, fmt.Errorf("no webauthn credentials found")
	}

	resp, err := s.webauthnSvc.BeginLogin(ctx, user, existingCredentials)
	if err != nil {
		return nil, err
	}

	return &WebAuthnBeginResponse{
		ChallengeID: resp.ChallengeID,
		Options:     resp.Options,
	}, nil
}

// FinishWebAuthnVerification 完成 WebAuthn 凭证验证
func (s *MFAService) FinishWebAuthnVerification(ctx context.Context, challengeID string, assertionBody []byte) (string, *WebAuthnCredentialInfo, error) {
	openid, credential, err := s.webauthnSvc.FinishLogin(ctx, challengeID, assertionBody)
	if err != nil {
		return "", nil, err
	}

	if credential != nil {
		if err := s.webauthnSvc.UpdateCredentialSignCount(ctx, base64.RawURLEncoding.EncodeToString(credential.ID), credential.Authenticator.SignCount); err != nil {
			logger.Warnf("failed to update webauthn credential sign count: %v", err)
		}
	}

	return openid, &WebAuthnCredentialInfo{
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
