package contract

import (
	"context"

	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
)

type HermesProvider interface {
	GetApplicationWithKey(ctx context.Context, appID string) (*models.ApplicationWithKey, error)
	GetServiceWithKey(ctx context.Context, serviceID string) (*models.ServiceWithKey, error)
	GetDomainWithKey(ctx context.Context, domainID string) (*models.DomainWithKey, error)
	GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error)
	GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error)
	GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error)
	FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error)
}

type UserProvider interface {
	GetUserWithDecrypted(ctx context.Context, openid string) (*models.UserWithDecrypted, error)
	GetIdentities(ctx context.Context, openid string) (models.Identities, error)
	GetIdentitiesByIdentity(ctx context.Context, identity *models.UserIdentity) (models.Identities, error)
	UpdateLastLogin(ctx context.Context, openid string) error
	GetByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error)
	GetByPhonePlain(ctx context.Context, phone string) (*models.UserWithDecrypted, error)
	AddIdentity(ctx context.Context, identity *models.UserIdentity) error
	CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error)
	GetUserByIdentifier(ctx context.Context, identifier string) (*hermes.PasswordStoreCredential, error)
	GetStaffByIdentifier(ctx context.Context, identifier string) (*hermes.PasswordStoreCredential, error)
	CreateCredential(ctx context.Context, cred *models.UserCredential) error
	UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error
	DeleteCredential(ctx context.Context, openid, credentialID string) error
	GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error)
	GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error)
	Update(ctx context.Context, openid string, updates map[string]any) error
	UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error
}

type CredentialProvider interface {
	VerifyTOTP(ctx context.Context, req *hermes.VerifyTOTPRequest) error
	GetUserMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error)
	GetUserCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error)
	SetupTOTP(ctx context.Context, req *hermes.TOTPSetupRequest) (*hermes.TOTPSetupResponse, error)
	ConfirmTOTP(ctx context.Context, req *hermes.ConfirmTOTPRequest) error
	SetTOTPEnabled(ctx context.Context, openid string, enabled bool) error
	SetWebAuthnEnabled(ctx context.Context, openid, credentialID string, enabled bool) error
	DisableTOTP(ctx context.Context, openid string) error
	DeleteWebAuthn(ctx context.Context, openid, credentialID string) error
}
