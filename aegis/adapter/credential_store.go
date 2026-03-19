package adapter

import (
	"context"

	amodels "github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/hermes"
)

// CredentialStoreAdapter 将 hermes.UserService 适配为 iris.CredentialStore
type CredentialStoreAdapter struct {
	svc *hermes.UserService
}

func NewCredentialStoreAdapter(svc *hermes.UserService) *CredentialStoreAdapter {
	return &CredentialStoreAdapter{svc: svc}
}

func (a *CredentialStoreAdapter) CreateCredential(ctx context.Context, cred *amodels.UserCredential) error {
	return a.svc.CreateCredential(ctx, ConvertCredentialToHermes(cred))
}

func (a *CredentialStoreAdapter) GetUserCredentials(ctx context.Context, openid string) ([]amodels.UserCredential, error) {
	cs, err := a.svc.GetUserCredentials(ctx, openid)
	if err != nil {
		return nil, err
	}
	return ConvertCredentials(cs), nil
}

func (a *CredentialStoreAdapter) GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]amodels.UserCredential, error) {
	cs, err := a.svc.GetUserCredentialsByType(ctx, openid, credType)
	if err != nil {
		return nil, err
	}
	return ConvertCredentials(cs), nil
}

func (a *CredentialStoreAdapter) GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]amodels.UserCredential, error) {
	cs, err := a.svc.GetEnabledUserCredentialsByType(ctx, openid, credType)
	if err != nil {
		return nil, err
	}
	return ConvertCredentials(cs), nil
}

func (a *CredentialStoreAdapter) GetCredentialByID(ctx context.Context, credentialID string) (*amodels.UserCredential, error) {
	c, err := a.svc.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	return ConvertCredential(c), nil
}

func (a *CredentialStoreAdapter) UpdateCredential(ctx context.Context, credentialID string, updates map[string]any) error {
	return a.svc.UpdateCredential(ctx, credentialID, updates)
}

func (a *CredentialStoreAdapter) EnableCredential(ctx context.Context, credentialID string) error {
	return a.svc.EnableCredential(ctx, credentialID)
}

func (a *CredentialStoreAdapter) DisableCredential(ctx context.Context, credentialID string) error {
	return a.svc.DisableCredential(ctx, credentialID)
}

func (a *CredentialStoreAdapter) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return a.svc.DeleteCredential(ctx, openid, credentialID)
}
