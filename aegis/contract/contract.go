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
	ListDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	GetService(ctx context.Context, serviceID string) (*models.Service, error)
	ListApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error)
	GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error)
}

type KeyProvider interface {
	GetKeys(ctx context.Context, ownerType, ownerID string) ([][]byte, error)
}

type RelationshipProvider interface {
	ListApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error)
	ListRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error)
}

type IDPKeyProvider interface {
	GetIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error)
}

type UserProvider interface {
	UserProfileProvider
	UserWriteProvider
	IdentityProvider
	CredentialStore
	GetPasswordLogin(ctx context.Context, idp, identifier string) (*models.PasswordLogin, error)
}

type UserProfileProvider interface {
	GetUserByOpenID(ctx context.Context, openid string) (*models.UserWithDecrypted, error)
	GetUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error)
	GetUserByPhone(ctx context.Context, phone string) (*models.UserWithDecrypted, error)
}

type UserWriteProvider interface {
	CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error)
	PatchUser(ctx context.Context, openid string, updates map[string]any) error
}

type IdentityProvider interface {
	ListUserIdentities(ctx context.Context, openid string) (models.Identities, error)
	ListIdentitiesByIdentity(ctx context.Context, domain, idp, tOpenID string) (models.Identities, error)
	CreateIdentity(ctx context.Context, identity *models.UserIdentity) error
}

type CredentialStore interface {
	CreateCredential(ctx context.Context, cred *models.UserCredential) error
	GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error)
	GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error)
	ListUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error)
	ListUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error)
	PatchCredential(ctx context.Context, credentialID string, updates map[string]any) error
	DeleteCredential(ctx context.Context, openid, credentialID string) error
	DeleteCredentialByOpenIDAndType(ctx context.Context, openid, credType string) error
}

type TOTPVerifier interface {
	VerifyTOTP(ctx context.Context, req *models.VerifyTOTPRequest) error
}
