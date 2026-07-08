package contract

import (
	"context"

	"github.com/heliannuuthus/aegis/models"
)

type HermesProvider interface {
	ProvisionProvider
	KeyProvider
	RelationshipProvider
	IDPKeyProvider
}

type ProvisionProvider interface {
	GetDomain(ctx context.Context, domainID string) (*models.Domain, error)
	GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	GetService(ctx context.Context, serviceID string) (*models.Service, error)
	GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error)
	GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error)
}

type KeyProvider interface {
	GetKeys(ctx context.Context, ownerType, ownerID string) ([][]byte, error)
}

type RelationshipProvider interface {
	GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error)
	FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error)
}

type IDPKeyProvider interface {
	ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error)
}

type UserProvider interface {
	UserProfileProvider
	IdentityProvider
	PasswordCredentialProvider
	UserCredentialProvider
}

type UserProfileProvider interface {
	GetDecryptedUserByOpenID(ctx context.Context, openid string) (*models.UserWithDecrypted, error)
	GetUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error)
	GetUserByPhone(ctx context.Context, phone string) (*models.UserWithDecrypted, error)
	PatchUser(ctx context.Context, openid string, updates map[string]any) error
}

type IdentityProvider interface {
	GetUserIdentitiesByOpenID(ctx context.Context, openid string) (models.Identities, error)
	GetIdentities(ctx context.Context, domain, idp, tOpenID string) (models.Identities, error)
	AddIdentity(ctx context.Context, identity *models.UserIdentity) error
	CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error)
}

type PasswordCredentialProvider interface {
	GetPasswordCredential(ctx context.Context, idp, identifier string) (*models.PasswordStoreCredential, error)
}

type UserCredentialProvider interface {
	CreateCredential(ctx context.Context, cred *models.UserCredential) error
	PatchCredential(ctx context.Context, credentialID string, updates map[string]any) error
	DeleteCredential(ctx context.Context, openid, credentialID string) error
	GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error)
	GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error)
}

// MFAProvider provides the MFA operations that back MFAService.
// HTTP handlers should depend on MFAService instead.
type MFAProvider interface {
	TOTPProvider
	WebAuthnCredentialProvider
	MFASummaryProvider
}

type TOTPProvider interface {
	SetupTOTP(ctx context.Context, req *models.TOTPSetupRequest) (*models.TOTPSetupResponse, error)
	ConfirmTOTP(ctx context.Context, req *models.ConfirmTOTPRequest) error
	VerifyTOTP(ctx context.Context, req *models.VerifyTOTPRequest) error
	DisableTOTP(ctx context.Context, openid string) error
	SetTOTPEnabled(ctx context.Context, openid string, enabled bool) error
}

type WebAuthnCredentialProvider interface {
	SetWebAuthnEnabled(ctx context.Context, openid, credentialID string, enabled bool) error
	RenameWebAuthn(ctx context.Context, openid, credentialID, label string) error
	DeleteWebAuthn(ctx context.Context, openid, credentialID string) error
}

type MFASummaryProvider interface {
	GetUserMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error)
	GetUserCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error)
}
