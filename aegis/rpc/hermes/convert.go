package hermes

import (
	"encoding/json"

	"github.com/heliannuuthus/helios/aegis/models"
	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
)

func domainFromProto(pb *hermesv1.Domain) *models.Domain {
	if pb == nil {
		return nil
	}
	return &models.Domain{
		DomainID:    pb.DomainId,
		Name:        pb.Name,
		Description: pb.Description,
	}
}

func applicationFromProto(pb *hermesv1.Application) *models.Application {
	if pb == nil {
		return nil
	}
	app := &models.Application{
		ID:                            uint(pb.Id),
		DomainID:                      pb.DomainId,
		AppID:                         pb.AppId,
		Name:                          pb.Name,
		Description:                   pb.Description,
		LogoURL:                       pb.LogoUrl,
		IDTokenExpiresIn:              uint(pb.IdTokenExpiresIn),
		RefreshTokenExpiresIn:         uint(pb.RefreshTokenExpiresIn),
		RefreshTokenAbsoluteExpiresIn: uint(pb.RefreshTokenAbsoluteExpiresIn),
	}
	app.AllowedRedirectURIs = marshalStringSlice(pb.AllowedRedirectUris)
	app.AllowedOrigins = marshalStringSlice(pb.AllowedOrigins)
	app.AllowedLogoutURIs = marshalStringSlice(pb.AllowedLogoutUris)
	if pb.CreatedAt != nil {
		app.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		app.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return app
}

func serviceFromProto(pb *hermesv1.Service) *models.Service {
	if pb == nil {
		return nil
	}
	svc := &models.Service{
		ID:                   uint(pb.Id),
		DomainID:             pb.DomainId,
		ServiceID:            pb.ServiceId,
		Name:                 pb.Name,
		Description:          pb.Description,
		LogoURL:              pb.LogoUrl,
		AccessTokenExpiresIn: uint(pb.AccessTokenExpiresIn),
	}
	if len(pb.RequiredIdentityTypes) > 0 {
		s := marshalStringSlice(pb.RequiredIdentityTypes)
		svc.RequiredIdentities = s
	}
	if pb.CreatedAt != nil {
		svc.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		svc.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	for _, cs := range pb.ChallengeSettings {
		svc.ChallengeSettings = append(svc.ChallengeSettings, *challengeSettingFromProto(cs))
	}
	return svc
}

func challengeSettingFromProto(pb *hermesv1.ServiceChallengeSetting) *models.ServiceChallengeSetting {
	if pb == nil {
		return nil
	}
	cs := &models.ServiceChallengeSetting{
		ID:        uint(pb.Id),
		ServiceID: pb.ServiceId,
		Type:      pb.Type,
		ExpiresIn: uint(pb.ExpiresIn),
	}
	if len(pb.Limits) > 0 {
		cs.Limits = make(models.RateLimits, len(pb.Limits))
		for k, v := range pb.Limits {
			cs.Limits[k] = int(v)
		}
	}
	if pb.CreatedAt != nil {
		cs.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		cs.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return cs
}

func idpConfigFromProto(pb *hermesv1.ApplicationIDPConfig) *models.ApplicationIDPConfig {
	if pb == nil {
		return nil
	}
	return &models.ApplicationIDPConfig{
		ID:       uint(pb.Id),
		AppID:    pb.AppId,
		Type:     pb.Type,
		Priority: int(pb.Priority),
		Strategy: pb.Strategy,
	}
}

func relationshipFromProto(pb *hermesv1.Relationship) *models.Relationship {
	if pb == nil {
		return nil
	}
	rel := &models.Relationship{
		ID:          uint(pb.Id),
		ServiceID:   pb.ServiceId,
		SubjectType: pb.SubjectType,
		SubjectID:   pb.SubjectId,
		Relation:    pb.Relation,
		ObjectType:  pb.ObjectType,
		ObjectID:    pb.ObjectId,
	}
	if pb.CreatedAt != nil {
		rel.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.ExpiresAt != nil {
		t := pb.ExpiresAt.AsTime()
		rel.ExpiresAt = &t
	}
	return rel
}

func appServiceRelationFromProto(pb *hermesv1.ApplicationServiceRelation) models.ApplicationServiceRelation {
	r := models.ApplicationServiceRelation{
		ID:        uint(pb.Id),
		AppID:     pb.AppId,
		ServiceID: pb.ServiceId,
		Relation:  pb.Relation,
	}
	if pb.CreatedAt != nil {
		r.CreatedAt = pb.CreatedAt.AsTime()
	}
	return r
}

func decryptedUserFromProto(pb *hermesv1.DecryptedUser) *models.UserWithDecrypted {
	if pb == nil {
		return nil
	}
	u := userFromProto(pb.User)
	if u == nil {
		return nil
	}
	return &models.UserWithDecrypted{
		User:  *u,
		Phone: pb.Phone,
	}
}

func userFromProto(pb *hermesv1.User) *models.User {
	if pb == nil {
		return nil
	}
	u := &models.User{
		ID:            uint(pb.Id),
		OpenID:        pb.Openid,
		Status:        int8(pb.Status),
		Nickname:      pb.Nickname,
		Picture:       pb.Picture,
		Email:         pb.Email,
		EmailVerified: pb.EmailVerified,
	}
	if pb.LastLoginAt != nil {
		t := pb.LastLoginAt.AsTime()
		u.LastLoginAt = &t
	}
	if pb.CreatedAt != nil {
		u.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		u.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return u
}

func identityFromProto(pb *hermesv1.UserIdentity) *models.UserIdentity {
	if pb == nil {
		return nil
	}
	id := &models.UserIdentity{
		ID:      uint(pb.Id),
		Domain:  pb.Domain,
		UID:     pb.Openid,
		IDP:     pb.Idp,
		TOpenID: pb.TOpenid,
	}
	if pb.RawData != nil {
		id.RawData = *pb.RawData
	}
	if pb.CreatedAt != nil {
		id.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		id.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return id
}

func credentialFromProto(pb *hermesv1.UserCredential) *models.UserCredential {
	if pb == nil {
		return nil
	}
	c := &models.UserCredential{
		ID:           uint(pb.Id),
		OpenID:       pb.Openid,
		CredentialID: pb.CredentialId,
		Type:         pb.Type,
		Enabled:      pb.Enabled,
		Secret:       pb.Secret,
	}
	if pb.LastUsedAt != nil {
		t := pb.LastUsedAt.AsTime()
		c.LastUsedAt = &t
	}
	if pb.CreatedAt != nil {
		c.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		c.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return c
}

func passwordStoreCredentialFromProto(pb *hermesv1.PasswordStoreCredential) *models.PasswordStoreCredential {
	if pb == nil {
		return nil
	}
	cred := &models.PasswordStoreCredential{
		OpenID:       pb.Openid,
		PasswordHash: pb.PasswordHash,
		Status:       int8(pb.Status),
	}
	if pb.Nickname != nil {
		cred.Nickname = *pb.Nickname
	}
	if pb.Email != nil {
		cred.Email = *pb.Email
	}
	if pb.Picture != nil {
		cred.Picture = *pb.Picture
	}
	return cred
}

// ==================== helpers ====================

func marshalStringSlice(s []string) *string {
	if len(s) == 0 {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	str := string(b)
	return &str
}
