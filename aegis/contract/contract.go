package contract

import (
	"context"

	"github.com/heliannuuthus/helios/aegis/models"
)

type HermesProvider interface {
	GetDomain(ctx context.Context, domainID string) (*models.Domain, error)
	GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error)
	GetApplication(ctx context.Context, appID string) (*models.Application, error)
	GetService(ctx context.Context, serviceID string) (*models.Service, error)
	GetDomainKeys(ctx context.Context, domainID string) ([][]byte, error)
	GetApplicationKeys(ctx context.Context, appID string) ([][]byte, error)
	GetServiceKeys(ctx context.Context, serviceID string) ([][]byte, error)
	GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error)
	GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error)
	GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error)
	FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error)
	ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error)
}

type UserProvider interface {
	GetDecryptedUserByOpenID(ctx context.Context, openid string) (*models.UserWithDecrypted, error)
	GetUserIdentitiesByOpenID(ctx context.Context, openid string) (models.Identities, error)
	GetIdentities(ctx context.Context, domain, idp, tOpenID string) (models.Identities, error)
	UpdateLastLogin(ctx context.Context, openid string) error
	GetUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error)
	GetUserByPhone(ctx context.Context, phone string) (*models.UserWithDecrypted, error)
	AddIdentity(ctx context.Context, identity *models.UserIdentity) error
	CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error)
	GetUserByIdentifier(ctx context.Context, identifier string) (*models.PasswordStoreCredential, error)
	GetStaffByIdentifier(ctx context.Context, identifier string) (*models.PasswordStoreCredential, error)
	CreateCredential(ctx context.Context, cred *models.UserCredential) error
	UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error
	DeleteCredential(ctx context.Context, openid, credentialID string) error
	GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error)
	GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error)
	UpdateUser(ctx context.Context, openid string, updates map[string]any) error
	UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error
}

// CredentialProvider 凭证业务接口（TOTP/WebAuthn 业务逻辑，由 iris 层实现）
type CredentialProvider interface {
	SetupTOTP(ctx context.Context, req *models.TOTPSetupRequest) (*models.TOTPSetupResponse, error)
	ConfirmTOTP(ctx context.Context, req *models.ConfirmTOTPRequest) error
	VerifyTOTP(ctx context.Context, req *models.VerifyTOTPRequest) error
	DisableTOTP(ctx context.Context, openid string) error
	SetTOTPEnabled(ctx context.Context, openid string, enabled bool) error
	SetWebAuthnEnabled(ctx context.Context, openid, credentialID string, enabled bool) error
	DeleteWebAuthn(ctx context.Context, openid, credentialID string) error
	GetUserMFAStatus(ctx context.Context, openid string) (*models.MFAStatus, error)
	GetUserCredentialSummaries(ctx context.Context, openid string) ([]models.CredentialSummary, error)
}
