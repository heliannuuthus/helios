package adapter

import (
	"context"

	amodels "github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/hermes"
)

// CredentialStoreAdapter 将 hermes.Service 适配为 iris.CredentialStore
type CredentialStoreAdapter struct {
	svc *hermes.Service
}

func NewCredentialStoreAdapter(svc *hermes.Service) *CredentialStoreAdapter {
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

func (a *CredentialStoreAdapter) UpdateCredentialByInternalID(ctx context.Context, id uint, updates map[string]any) error {
	return a.svc.UpdateCredentialByInternalID(ctx, id, updates)
}

func (a *CredentialStoreAdapter) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return a.svc.DeleteCredential(ctx, openid, credentialID)
}

func (a *CredentialStoreAdapter) DeleteCredentialByOpenIDAndType(ctx context.Context, openid, credType string) error {
	return a.svc.DeleteCredentialByOpenIDAndType(ctx, openid, credType)
}
