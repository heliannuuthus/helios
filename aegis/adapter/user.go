package adapter

import (
	"context"

	amodels "github.com/heliannuuthus/helios/aegis/models"
	"github.com/heliannuuthus/helios/hermes"
)

// UserAdapter 将 hermes.Service 适配为 contract.UserProvider
type UserAdapter struct {
	svc *hermes.Service
}

func NewUserAdapter(svc *hermes.Service) *UserAdapter {
	return &UserAdapter{svc: svc}
}

func (a *UserAdapter) GetDecryptedUserByOpenID(ctx context.Context, openid string) (*amodels.UserWithDecrypted, error) {
	u, err := a.svc.GetDecryptedUserByOpenID(ctx, openid)
	if err != nil {
		return nil, err
	}
	return ConvertUserWithDecrypted(u), nil
}

func (a *UserAdapter) GetUserIdentitiesByOpenID(ctx context.Context, openid string) (amodels.Identities, error) {
	ids, err := a.svc.GetUserIdentitiesByOpenID(ctx, openid)
	if err != nil {
		return nil, err
	}
	return ConvertIdentities(ids), nil
}

func (a *UserAdapter) GetIdentities(ctx context.Context, domain, idp, tOpenID string) (amodels.Identities, error) {
	ids, err := a.svc.GetIdentities(ctx, domain, idp, tOpenID)
	if err != nil {
		return nil, err
	}
	return ConvertIdentities(ids), nil
}

func (a *UserAdapter) UpdateLastLogin(ctx context.Context, openid string) error {
	return a.svc.UpdateLastLogin(ctx, openid)
}

func (a *UserAdapter) GetUserByEmail(ctx context.Context, email string) (*amodels.UserWithDecrypted, error) {
	u, err := a.svc.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return ConvertUserWithDecrypted(u), nil
}

func (a *UserAdapter) GetUserByPhone(ctx context.Context, phone string) (*amodels.UserWithDecrypted, error) {
	u, err := a.svc.GetUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}
	return ConvertUserWithDecrypted(u), nil
}

func (a *UserAdapter) AddIdentity(ctx context.Context, identity *amodels.UserIdentity) error {
	return a.svc.AddIdentity(ctx, ConvertIdentityPtr(identity))
}

func (a *UserAdapter) CreateUser(ctx context.Context, identity *amodels.UserIdentity, userInfo *amodels.TUserInfo) (*amodels.UserWithDecrypted, error) {
	u, err := a.svc.CreateUser(ctx, ConvertIdentityPtr(identity), ConvertTUserInfo(userInfo))
	if err != nil {
		return nil, err
	}
	return ConvertUserWithDecrypted(u), nil
}

func (a *UserAdapter) GetUserByIdentifier(ctx context.Context, identifier string) (*amodels.PasswordStoreCredential, error) {
	c, err := a.svc.GetUserByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return ConvertPasswordStoreCredential(c), nil
}

func (a *UserAdapter) GetStaffByIdentifier(ctx context.Context, identifier string) (*amodels.PasswordStoreCredential, error) {
	c, err := a.svc.GetStaffByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return ConvertPasswordStoreCredential(c), nil
}

func (a *UserAdapter) CreateCredential(ctx context.Context, cred *amodels.UserCredential) error {
	return a.svc.CreateCredential(ctx, ConvertCredentialToHermes(cred))
}

func (a *UserAdapter) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return a.svc.UpdateCredentialSignCount(ctx, credentialID, signCount)
}

func (a *UserAdapter) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	return a.svc.DeleteCredential(ctx, openid, credentialID)
}

func (a *UserAdapter) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	return a.svc.GetOpenIDByCredentialID(ctx, credentialID)
}

func (a *UserAdapter) GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]amodels.UserCredential, error) {
	cs, err := a.svc.GetEnabledUserCredentialsByType(ctx, openid, credType)
	if err != nil {
		return nil, err
	}
	return ConvertCredentials(cs), nil
}

func (a *UserAdapter) UpdateUser(ctx context.Context, openid string, updates map[string]any) error {
	return a.svc.UpdateUser(ctx, openid, updates)
}

func (a *UserAdapter) UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error {
	return a.svc.UpdatePassword(ctx, openid, oldPassword, newPassword)
}
