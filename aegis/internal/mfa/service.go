package mfa

import (
	"context"
	"net/http"

	"github.com/heliannuuthus/aegis/internal/authenticator/totp"
	"github.com/heliannuuthus/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
)

// Service coordinates MFA enrollment and credential management.
type Service struct {
	credentials *CredentialService
	totp        *totp.Service
	webauthnSvc *webauthn.Service
}

func NewService(credentials *hermes.Client, cacheManager *cache.Manager, webauthnSvc *webauthn.Service) *Service {
	credentialSvc := NewCredentialService(credentials)
	totpSvc := totp.NewService(credentials, cacheManager)
	return &Service{
		credentials: credentialSvc,
		totp:        totpSvc,
		webauthnSvc: webauthnSvc,
	}
}

func (s *Service) TOTP() *totp.Service {
	return s.totp
}

func (s *Service) GetRPID() string {
	return s.webauthnSvc.GetRPID()
}

func (s *Service) CreateTOTPEnrollment(ctx context.Context, openid, appName string) (*totp.Enrollment, error) {
	return s.totp.BeginEnrollment(ctx, openid, appName)
}

func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, openid, uid, code string) error {
	return s.totp.ConfirmEnrollment(ctx, openid, uid, code)
}

func (s *Service) UpdateCredential(ctx context.Context, openid, credType, credentialID string, updates map[string]any) error {
	return s.credentials.Update(ctx, openid, credType, credentialID, updates)
}

func (s *Service) DeleteCredential(ctx context.Context, openid, credType, credentialID string) error {
	return s.credentials.Delete(ctx, openid, credType, credentialID)
}

func (s *Service) Status(ctx context.Context, openid string) (*models.MFAStatus, error) {
	return s.credentials.Status(ctx, openid)
}

func (s *Service) ListCredentials(ctx context.Context, openid string) ([]models.CredentialSummary, error) {
	return s.credentials.List(ctx, openid)
}

func (s *Service) CreateWebAuthnEnrollment(ctx context.Context, user *models.UserWithDecrypted) (*models.WebAuthnBeginResponse, error) {
	existingCredentials, err := s.webauthnSvc.ListCredentials(ctx, user.OpenID)
	if err != nil {
		existingCredentials = nil
	}

	resp, err := s.webauthnSvc.InitializeRegistration(ctx, user, existingCredentials)
	if err != nil {
		return nil, err
	}

	return &models.WebAuthnBeginResponse{
		ChallengeID: resp.CeremonyID,
		Options:     resp.Options,
	}, nil
}

func (s *Service) ConfirmWebAuthnEnrollment(ctx context.Context, openid, challengeID string, r *http.Request) (*models.WebAuthnCredentialInfo, error) {
	credential, err := s.webauthnSvc.CompleteRegistration(ctx, challengeID, r)
	if err != nil {
		return nil, err
	}

	if err := s.webauthnSvc.SaveCredential(ctx, openid, credential); err != nil {
		return nil, err
	}

	return &models.WebAuthnCredentialInfo{
		ID:        credential.ID,
		SignCount: credential.Authenticator.SignCount,
	}, nil
}

func (s *Service) HasWebAuthnCredentials(ctx context.Context, openid string) (bool, error) {
	creds, err := s.webauthnSvc.ListCredentials(ctx, openid)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}
